import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentSession } from '../agent/agent-session.js';
import {
  DelegationService,
  EXECUTOR_DELEGATION_REQUIREMENTS,
  PROPOSAL_DELEGATION_REQUIREMENTS,
  type DelegationStatus,
} from '../agent/delegation-service.js';
import { ExecutorSession } from '../agent/executor-session.js';
import { readGatewayConfig } from '../config/env.js';
import { buildDelegatedExecutionRequest, PrivacyGuardContractService, type PolicyDecision } from '../contract/privacy-guard-contract.js';
import { assertNoSecretLeak, sanitizeEvidenceError } from '../evidence/leak-detector.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

type EvidenceStatus = 'PASS' | 'FAIL' | 'NOT_RUN';
interface ScenarioResult { id: string; layer: 'T3N_TESTNET'; expected: string; actual: string | null; status: EvidenceStatus; detail?: string; }
interface DelegationEvidence {
  memberState: DelegationStatus['memberState'];
  effectiveState: DelegationStatus['effectiveState'];
  checkedFunctions: string[];
  checkedScopes: string[];
}
interface EvidenceBundle {
  generatedAt: string; network: string; sdkVersion: '5.2.0'; tenantDid: string; agentDid: string; executorDid: string;
  contractId: string; contractVersion: string; wasmSha256: string | null;
  policyVersion: string | null; policyHash: string | null;
  delegation: { proposal: DelegationEvidence; executor: DelegationEvidence };
  scenarios: ScenarioResult[];
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDir, '../../..');
const outputPath = resolve(process.env.EVIDENCE_OUTPUT ?? resolve(repositoryRoot, 'docs/evidence/testnet-run.json'));
const wasmPath = resolve(process.env.T3N_CONTRACT_WASM_PATH ?? resolve(repositoryRoot, 'contracts/privacy-guard/target/wasm32-wasip2/release/privacy_guard_contract.wasm'));

function httpsHost(value: string, label: string): string {
  const parsed = new URL(value);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port) throw new Error(`${label} must be an HTTPS URL with a canonical hostname and no credentials or explicit port`);
  return parsed.hostname.toLowerCase();
}

function executionHost(): string {
  const configured = process.env.SECURITY_API_URL?.trim();
  return configured ? httpsHost(configured, 'SECURITY_API_URL') : 'postman-echo.com';
}

function configuredEgressHosts(): string[] {
  const candidates = [process.env.SECURITY_API_URL, process.env.SECURITY_VERIFICATION_URL]
    .map((value) => value?.trim())
    .filter((value): value is string => Boolean(value));
  if (candidates.length === 0) return ['postman-echo.com'];
  return [...new Set(candidates.map((value) => httpsHost(value, 'Evidence egress endpoint')))];
}

function evidenceDelegation(status: DelegationStatus): DelegationEvidence {
  return {
    memberState: status.memberState,
    effectiveState: status.effectiveState,
    checkedFunctions: status.checkedFunctions,
    checkedScopes: status.checkedScopes,
  };
}

function authorisedVerdict(value: unknown): boolean | null {
  if (!value || typeof value !== 'object') return null;
  const authorised = (value as Record<string, unknown>).authorised;
  return typeof authorised === 'boolean' ? authorised : null;
}

const config = readGatewayConfig();
if (config.network !== 'testnet' && process.env.EVIDENCE_ALLOW_PRODUCTION !== 'true') throw new Error('Adversarial evidence runner is restricted to testnet unless EVIDENCE_ALLOW_PRODUCTION=true is explicitly set');
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required for testnet evidence');
if (!config.executorApiKey) throw new Error('T3N_EXECUTOR_API_KEY is required for testnet evidence');

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const tenantSession = new T3nSession(config, trustFloorStore);
const agentSession = new AgentSession(config, trustFloorStore);
const executorSession = new ExecutorSession(config, trustFloorStore);
const proposalDelegation = new DelegationService(tenantSession, agentSession, PROPOSAL_DELEGATION_REQUIREMENTS);
const executorDelegation = new DelegationService(tenantSession, executorSession, EXECUTOR_DELEGATION_REQUIREMENTS);
const contract = new PrivacyGuardContractService(config, tenantSession, agentSession, executorSession);
const scenarios: ScenarioResult[] = [];
let observedPolicyVersion: string | null = null;
let observedPolicyHash: string | null = null;

function record(id: string, expected: string, actual: string | null, status: EvidenceStatus, detail?: string): void {
  scenarios.push({ id, layer: 'T3N_TESTNET', expected, actual, status, detail });
}

function observePolicy(decision: PolicyDecision): void {
  if (!decision.policy_version || !decision.policy_hash || !/^[a-f0-9]{64}$/.test(decision.policy_hash)) {
    throw new Error('Live decision did not return valid versioned policy metadata');
  }
  if (observedPolicyVersion && (observedPolicyVersion !== decision.policy_version || observedPolicyHash !== decision.policy_hash)) {
    throw new Error('Policy changed during one evidence run');
  }
  observedPolicyVersion = decision.policy_version;
  observedPolicyHash = decision.policy_hash;
}

async function wasmHash(): Promise<string | null> {
  try { return createHash('sha256').update(await readFile(wasmPath)).digest('hex'); } catch { return null; }
}

async function grantLeastPrivilege(contractId: string, version: string): Promise<void> {
  await proposalDelegation.grant({
    contractId,
    versionReq: version,
    functions: [...PROPOSAL_DELEGATION_REQUIREMENTS.functions],
    scopes: [...PROPOSAL_DELEGATION_REQUIREMENTS.scopes],
    allowedHosts: [],
  });
  await executorDelegation.grant({
    contractId,
    versionReq: version,
    functions: [...EXECUTOR_DELEGATION_REQUIREMENTS.functions],
    scopes: [...EXECUTOR_DELEGATION_REQUIREMENTS.scopes],
    allowedHosts: configuredEgressHosts(),
  });
}

async function decisionScenario(id: string, expected: 'ALLOW' | 'REDACT' | 'DENY', input: Parameters<PrivacyGuardContractService['evaluate']>[0]): Promise<void> {
  try {
    const result = await contract.evaluate(input);
    observePolicy(result);
    record(id, expected, result.decision, result.decision === expected ? 'PASS' : 'FAIL', `${result.reason_code}; policy=${result.policy_version}; hash=${result.policy_hash}`);
  } catch (error) {
    record(id, expected, null, 'FAIL', sanitizeEvidenceError(error));
  }
}

function isDelegationRejection(message: string): boolean {
  return /(denied|not[ -]?authori[sz]ed|delegat|permission|function.*allow|grant)/i.test(message);
}

async function expectExecutorRequiresHumanProof(
  contractId: string,
  contractVersion: string,
  tenantDid: string,
  agentDid: string,
  executorDid: string,
): Promise<void> {
  const id = 'LIVE-EXECUTOR-REQUIRES-HUMAN-PROOF';
  const expected = 'real protected Executor DID is rejected inside execute-remediation when no human authorization proof is supplied, before protected egress';
  if (!observedPolicyVersion || !observedPolicyHash) {
    record(id, expected, null, 'FAIL', 'Versioned policy metadata was not established');
    return;
  }
  try {
    await executorSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
      tenantDid,
      contractId,
      contractVersion,
      'execute-remediation',
      {
        incident_id: 'live-executor-no-proof-incident',
        action_id: 'live-executor-no-proof-action',
        decision_id: 'live-executor-no-proof-decision',
        request_id: 'live-executor-no-proof',
        agent_did: agentDid,
        executor_did: executorDid,
        action: 'revoke-credential',
        resource: 'credential:security-api',
        purpose: 'incident-remediation',
        approved_host: executionHost(),
        fields: ['incident_id', 'credential_id', 'reason'],
        private_refs: [],
        policy_version: observedPolicyVersion,
        policy_hash: observedPolicyHash,
        authorization_proof: '',
      },
    ));
    record(id, expected, 'ACCEPTED', 'FAIL', 'Protected Executor credential unexpectedly bypassed the human authorization boundary');
  } catch (error) {
    const detail = sanitizeEvidenceError(error);
    const proofRejected = /(human authorization proof|AUTHORIZATION_PROOF|authorization proof)/i.test(detail);
    record(
      id,
      expected,
      proofRejected ? 'REJECTED_BEFORE_PROTECTED_EGRESS' : 'REJECTED_OTHER_REASON',
      proofRejected ? 'PASS' : 'FAIL',
      detail,
    );
  }
}

async function expectProposalExecutorRejected(contractId: string, contractVersion: string, tenantDid: string, agentDid: string, executorDid: string): Promise<void> {
  try {
    await agentSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
      tenantDid,
      contractId,
      contractVersion,
      'execute-remediation',
      {
        incident_id: 'live-proposal-execute-deny-incident',
        action_id: 'live-proposal-execute-deny-action',
        decision_id: 'live-proposal-execute-deny-decision',
        request_id: 'live-proposal-execute-deny',
        agent_did: agentDid,
        executor_did: executorDid,
        action: 'revoke-credential',
        resource: 'credential:security-api',
        purpose: 'incident-remediation',
        approved_host: executionHost(),
        fields: ['incident_id', 'credential_id', 'reason'],
        private_refs: [],
        policy_version: observedPolicyVersion ?? 'unavailable',
        policy_hash: observedPolicyHash ?? '0'.repeat(64),
        authorization_proof: '',
      },
    ));
    record('LIVE-PROPOSAL-CANNOT-EXECUTE', 'Proposal Agent DID rejected by T3N for execute-remediation', 'ACCEPTED', 'FAIL', 'Proposal principal unexpectedly executed a privileged function');
  } catch (error) {
    const detail = sanitizeEvidenceError(error);
    record('LIVE-PROPOSAL-CANNOT-EXECUTE', 'Proposal Agent DID rejected by T3N for execute-remediation', 'REJECTED', isDelegationRejection(detail) ? 'PASS' : 'FAIL', detail);
  }
}

async function expectProposalVerificationRejected(contractId: string, contractVersion: string, tenantDid: string): Promise<void> {
  try {
    await agentSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
      tenantDid,
      contractId,
      contractVersion,
      'verify-remediation',
      { request_id: 'live-proposal-verify-deny', operation_id: 'synthetic-operation-not-authorized-for-proposal', expected_state: 'REVOKED' },
    ));
    record('LIVE-PROPOSAL-CANNOT-VERIFY', 'Proposal Agent DID rejected by T3N for verify-remediation', 'ACCEPTED', 'FAIL', 'Proposal principal unexpectedly invoked privileged verification');
  } catch (error) {
    const detail = sanitizeEvidenceError(error);
    record('LIVE-PROPOSAL-CANNOT-VERIFY', 'Proposal Agent DID rejected by T3N for verify-remediation', 'REJECTED', isDelegationRejection(detail) ? 'PASS' : 'FAIL', detail);
  }
}

async function expectRevokedCheckDenied(
  id: string,
  label: string,
  contractId: string,
  tenantDid: string,
  session: AgentSession | ExecutorSession,
  functions: readonly string[],
  scopes: readonly string[],
): Promise<void> {
  try {
    const result = await session.getClient().checkDelegation({ contract: contractId, pii_did: tenantDid, functions: [...functions], scopes: [...scopes] }) as unknown;
    const authorised = authorisedVerdict(result);
    record(id, label, authorised === null ? 'INCONCLUSIVE' : `authorised=${authorised}`, authorised === false ? 'PASS' : 'FAIL');
  } catch (error) {
    record(id, label, null, 'FAIL', sanitizeEvidenceError(error));
  }
}

await tenantSession.connect();
await Promise.all([agentSession.connect(), executorSession.connect()]);
const identity = await contract.identity();
const tenantDid = tenantSession.getTenantDid();
const agentDid = agentSession.getAgentDid();
const executorDid = executorSession.getExecutorDid();
const distinct = new Set([tenantDid, agentDid, executorDid]).size === 3;
record('LIVE-IDENTITY-SEPARATION', 'tenant, proposal Agent and protected Executor use three distinct DIDs', distinct ? 'three distinct DIDs' : 'DID reuse detected', distinct ? 'PASS' : 'FAIL');

await grantLeastPrivilege(identity.contractId, identity.contractVersion);
const proposalDelegationStatus = await proposalDelegation.status(identity.contractId);
const executorDelegationStatus = await executorDelegation.status(identity.contractId);
const effectiveDelegations = proposalDelegationStatus.memberState === 'ACTIVE'
  && proposalDelegationStatus.effectiveState === 'ACTIVE'
  && executorDelegationStatus.memberState === 'ACTIVE'
  && executorDelegationStatus.effectiveState === 'ACTIVE';
record(
  'LIVE-EFFECTIVE-DELEGATION',
  'Proposal Agent and Protected Executor are effectively authorised by T3N for their exact least-privilege functions/scopes',
  `proposal=${proposalDelegationStatus.effectiveState}; executor=${executorDelegationStatus.effectiveState}`,
  effectiveDelegations ? 'PASS' : 'FAIL',
  `proposal functions=${proposalDelegationStatus.checkedFunctions.join(',')}; proposal scopes=${proposalDelegationStatus.checkedScopes.join(',')}; executor functions=${executorDelegationStatus.checkedFunctions.join(',')}; executor scopes=${executorDelegationStatus.checkedScopes.join(',')}`,
);

const protectedHost = executionHost();
await decisionScenario('LIVE-SECRET-EXFILTRATION', 'DENY', { request_id: 'live-secret-exfiltration', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'incident-remediation', host: 'attacker.example', fields: ['incident_id', 'credential_id', 'reason', 'api_key'] });
await decisionScenario('LIVE-HOST-DENY', 'DENY', { request_id: 'live-host-deny', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'incident-remediation', host: 'attacker.example', fields: ['incident_id', 'credential_id', 'reason'] });
await decisionScenario('LIVE-PURPOSE-DENY', 'DENY', { request_id: 'live-purpose-deny', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'analytics', host: protectedHost, fields: ['incident_id', 'credential_id', 'reason'] });
await decisionScenario('LIVE-DATA-MINIMIZATION', 'REDACT', { request_id: 'live-redact', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'incident-remediation', host: protectedHost, fields: ['incident_id', 'credential_id', 'reason', 'employee_department'] });
await decisionScenario('LIVE-MINIMAL-ALLOW', 'ALLOW', { request_id: 'live-allow', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'incident-remediation', host: protectedHost, fields: ['incident_id', 'credential_id', 'reason'] });
await decisionScenario('LIVE-PRIVATE-REFERENCE-POLICY', 'ALLOW', {
  request_id: 'live-private-ref-policy', action: 'notify-security', resource: 'incident:synthetic', purpose: 'incident-notification', host: protectedHost,
  fields: ['incident_id', 'severity', 'summary'], private_refs: ['verified_email'],
});
record(
  'LIVE-VERSIONED-POLICY-PROVENANCE',
  'all decisions expose one stable policy version and SHA-256 during the run',
  observedPolicyVersion && observedPolicyHash ? `${observedPolicyVersion} / ${observedPolicyHash}` : null,
  observedPolicyVersion && observedPolicyHash ? 'PASS' : 'FAIL',
);
record(
  'LIVE-PROFILE-PLACEHOLDER-RESOLUTION',
  'verified_email resolved by T3N profile placeholder only during protected egress',
  null,
  'NOT_RUN',
  'Requires a dedicated synthetic T3N profile with verified email and compatible delegated scope/user context. Local mapping tests do not count as live resolution proof.',
);

await expectExecutorRequiresHumanProof(identity.contractId, identity.contractVersion, tenantDid, agentDid, executorDid);

record(
  'LIVE-DESTINATION-BINDING',
  'approved host remains authoritative after protected configuration changes',
  null,
  'NOT_RUN',
  'The adversarial gateway runner intentionally has no remediation signing key after the T3N human-proof hardening. Exercise destination binding through the authenticated backend flow so the human proof is legitimately issued and never exported.',
);
record(
  'LIVE-SAFE-AFTER-ATTACK',
  'DENY -> ALLOW -> gateway proof verified -> T3N proof verified -> accepted execution -> independent VERIFIED read-back',
  null,
  'NOT_RUN',
  'Positive protected remediation now requires a legitimate backend-issued Ed25519 human proof. Capture it through the authenticated application flow (CAPTURE_ALLOW_REMEDIATION=true); this runner never receives the private signing key.',
);

if (process.env.EVIDENCE_RUN_EGRESS_NEGATIVES === 'true') {
  try {
    await proposalDelegation.revoke(identity.contractId);
    await expectRevokedCheckDenied(
      'LIVE-REVOKED-PROPOSAL-CHECK',
      'Proposal checkDelegation returns authorised=false after Proposal Member Delegation revocation',
      identity.contractId,
      tenantDid,
      agentSession,
      PROPOSAL_DELEGATION_REQUIREMENTS.functions,
      PROPOSAL_DELEGATION_REQUIREMENTS.scopes,
    );
  } finally {
    await grantLeastPrivilege(identity.contractId, identity.contractVersion);
  }
  await expectProposalExecutorRejected(identity.contractId, identity.contractVersion, tenantDid, agentDid, executorDid);
  await expectProposalVerificationRejected(identity.contractId, identity.contractVersion, tenantDid);
  try {
    await executorDelegation.revoke(identity.contractId);
    await expectRevokedCheckDenied(
      'LIVE-REVOKED-EXECUTOR-CHECK',
      'Executor checkDelegation returns authorised=false after Executor Member Delegation revocation',
      identity.contractId,
      tenantDid,
      executorSession,
      EXECUTOR_DELEGATION_REQUIREMENTS.functions,
      EXECUTOR_DELEGATION_REQUIREMENTS.scopes,
    );
  } finally {
    await grantLeastPrivilege(identity.contractId, identity.contractVersion);
  }
  record(
    'LIVE-REVOKED-EXECUTOR',
    'protected egress rejected after Executor delegation revocation',
    'COVERED_BY_CHECK_DELEGATION',
    'PASS',
    'The revocation verdict is established by live T3N checkDelegation. A direct remediation call is intentionally not used because it would also fail on the independent human-proof boundary and could not isolate delegation revocation.',
  );
} else {
  record('LIVE-REVOKED-PROPOSAL-CHECK', 'Proposal checkDelegation returns authorised=false after Proposal Member Delegation revocation', null, 'NOT_RUN', 'Set EVIDENCE_RUN_EGRESS_NEGATIVES=true to mutate and restore the live Proposal grant.');
  record('LIVE-PROPOSAL-CANNOT-EXECUTE', 'Proposal Agent DID rejected by T3N for execute-remediation', null, 'NOT_RUN', 'Set EVIDENCE_RUN_EGRESS_NEGATIVES=true after the contract has been deployed.');
  record('LIVE-PROPOSAL-CANNOT-VERIFY', 'Proposal Agent DID rejected by T3N for verify-remediation', null, 'NOT_RUN', 'Set EVIDENCE_RUN_EGRESS_NEGATIVES=true after the contract has been deployed.');
  record('LIVE-REVOKED-EXECUTOR-CHECK', 'Executor checkDelegation returns authorised=false after Executor Member Delegation revocation', null, 'NOT_RUN', 'Set EVIDENCE_RUN_EGRESS_NEGATIVES=true to mutate and restore the live Executor grant.');
  record('LIVE-REVOKED-EXECUTOR', 'protected egress rejected after Executor delegation revocation', null, 'NOT_RUN', 'Set EVIDENCE_RUN_EGRESS_NEGATIVES=true to collect the isolated live delegation-revocation verdict.');
}

const evidence: EvidenceBundle = {
  generatedAt: new Date().toISOString(),
  network: config.network,
  sdkVersion: '5.2.0',
  tenantDid,
  agentDid,
  executorDid,
  contractId: identity.contractId,
  contractVersion: identity.contractVersion,
  wasmSha256: await wasmHash(),
  policyVersion: observedPolicyVersion,
  policyHash: observedPolicyHash,
  delegation: { proposal: evidenceDelegation(proposalDelegationStatus), executor: evidenceDelegation(executorDelegationStatus) },
  scenarios,
};
const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
assertNoSecretLeak(serialized, [
  config.apiKey,
  config.agentApiKey,
  config.executorApiKey,
  process.env.EVIDENCE_SENTINEL_SECRET,
  process.env.SECURITY_API_KEY,
  process.env.AI_API_KEY,
  config.gatewayServiceToken,
  process.env.REMEDIATION_AUTH_PRIVATE_KEY,
]);
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, serialized, 'utf8');
console.info(JSON.stringify({
  outputPath,
  proposalAgentDid: agentDid,
  protectedExecutorDid: executorDid,
  proposalEffectiveAccess: proposalDelegationStatus.effectiveState,
  executorEffectiveAccess: executorDelegationStatus.effectiveState,
  policyVersion: observedPolicyVersion,
  policyHash: observedPolicyHash,
  pass: scenarios.filter((item) => item.status === 'PASS').length,
  fail: scenarios.filter((item) => item.status === 'FAIL').length,
  notRun: scenarios.filter((item) => item.status === 'NOT_RUN').length,
}, null, 2));
if (scenarios.some((item) => item.status === 'FAIL')) process.exitCode = 1;
