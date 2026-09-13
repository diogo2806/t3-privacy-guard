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

function configuredEgressHosts(): string[] {
  const configured = [process.env.SECURITY_API_URL, process.env.SECURITY_VERIFICATION_URL]
    .map((value) => value?.trim())
    .filter((value): value is string => Boolean(value));
  if (configured.length === 0) return ['postman-echo.com'];
  return [...new Set(configured.map((value) => {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:') throw new Error('Evidence egress endpoints must use HTTPS');
    return parsed.hostname;
  }))];
}

function evidenceDelegation(status: DelegationStatus): DelegationEvidence {
  return {
    memberState: status.memberState,
    effectiveState: status.effectiveState,
    checkedFunctions: status.checkedFunctions,
    checkedScopes: status.checkedScopes,
  };
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
  } catch (error) { record(id, expected, null, 'FAIL', sanitizeEvidenceError(error)); }
}
function isAuthorizationRejection(message: string): boolean {
  return /(egress|denied|not[ -]?authori[sz]ed|authori[sz]ation|delegat|permission|function.*allow|grant)/i.test(message);
}
async function expectProposalExecutorRejected(contractId: string, contractVersion: string, tenantDid: string, agentDid: string): Promise<void> {
  if (!observedPolicyVersion || !observedPolicyHash) {
    record('LIVE-PROPOSAL-CANNOT-EXECUTE', 'Proposal Agent DID rejected by T3N for execute-remediation', null, 'FAIL', 'Versioned policy metadata was not established');
    return;
  }
  try {
    await agentSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
      tenantDid,
      contractId,
      contractVersion,
      'execute-remediation',
      {
        request_id: 'live-proposal-execute-deny',
        agent_did: agentDid,
        action: 'revoke-credential',
        resource: 'credential:security-api',
        purpose: 'incident-remediation',
        fields: ['incident_id', 'credential_id', 'reason'],
        private_refs: [],
        policy_version: observedPolicyVersion,
        policy_hash: observedPolicyHash,
      },
    ));
    record('LIVE-PROPOSAL-CANNOT-EXECUTE', 'Proposal Agent DID rejected by T3N for execute-remediation', 'ACCEPTED', 'FAIL', 'Proposal principal unexpectedly executed a privileged function');
  } catch (error) {
    const detail = sanitizeEvidenceError(error);
    record('LIVE-PROPOSAL-CANNOT-EXECUTE', 'Proposal Agent DID rejected by T3N for execute-remediation', 'REJECTED', isAuthorizationRejection(detail) ? 'PASS' : 'FAIL', detail);
  }
}
async function expectExecutorRevocationRejected(id: string, expected: string, requestId: string, executorDid: string): Promise<void> {
  if (!observedPolicyVersion || !observedPolicyHash) {
    record(id, expected, null, 'FAIL', 'Versioned policy metadata was not established before protected egress');
    return;
  }
  try {
    const result = await contract.remediate({
      request_id: requestId,
      action: 'revoke-credential',
      resource: 'credential:security-api',
      purpose: 'incident-remediation',
      fields: ['incident_id', 'credential_id', 'reason'],
      policy_version: observedPolicyVersion,
      policy_hash: observedPolicyHash,
    }, executorDid);
    record(id, expected, result.status, 'FAIL', 'Protected egress unexpectedly reached the acceptance state');
  } catch (error) {
    const detail = sanitizeEvidenceError(error);
    record(id, expected, 'REJECTED', isAuthorizationRejection(detail) ? 'PASS' : 'FAIL', detail);
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

await decisionScenario('LIVE-SECRET-EXFILTRATION', 'DENY', { request_id: 'live-secret-exfiltration', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'incident-remediation', host: 'attacker.example', fields: ['incident_id', 'credential_id', 'reason', 'api_key'] });
await decisionScenario('LIVE-HOST-DENY', 'DENY', { request_id: 'live-host-deny', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'incident-remediation', host: 'attacker.example', fields: ['incident_id', 'credential_id', 'reason'] });
await decisionScenario('LIVE-PURPOSE-DENY', 'DENY', { request_id: 'live-purpose-deny', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'analytics', host: 'postman-echo.com', fields: ['incident_id', 'credential_id', 'reason'] });
await decisionScenario('LIVE-DATA-MINIMIZATION', 'REDACT', { request_id: 'live-redact', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'incident-remediation', host: 'postman-echo.com', fields: ['incident_id', 'credential_id', 'reason', 'employee_department'] });
await decisionScenario('LIVE-MINIMAL-ALLOW', 'ALLOW', { request_id: 'live-allow', action: 'revoke-credential', resource: 'credential:security-api', purpose: 'incident-remediation', host: 'postman-echo.com', fields: ['incident_id', 'credential_id', 'reason'] });
await decisionScenario('LIVE-PRIVATE-REFERENCE-POLICY', 'ALLOW', {
  request_id: 'live-private-ref-policy', action: 'notify-security', resource: 'incident:synthetic', purpose: 'incident-notification', host: 'postman-echo.com',
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

if (process.env.EVIDENCE_RUN_EGRESS_NEGATIVES === 'true') {
  await expectProposalExecutorRejected(identity.contractId, identity.contractVersion, tenantDid, agentDid);
  try {
    await executorDelegation.revoke(identity.contractId);
    await expectExecutorRevocationRejected('LIVE-REVOKED-EXECUTOR', 'protected egress rejected after Executor delegation revocation', 'live-revoked-executor-deny', executorDid);
  } finally { await grantLeastPrivilege(identity.contractId, identity.contractVersion); }
} else {
  record('LIVE-PROPOSAL-CANNOT-EXECUTE', 'Proposal Agent DID rejected by T3N for execute-remediation', null, 'NOT_RUN', 'Set EVIDENCE_RUN_EGRESS_NEGATIVES=true after the private remediation map has been seeded.');
  record('LIVE-REVOKED-EXECUTOR', 'protected egress rejected after Executor delegation revocation', null, 'NOT_RUN', 'Set EVIDENCE_RUN_EGRESS_NEGATIVES=true after the private remediation map has been seeded.');
}

if (process.env.EVIDENCE_RUN_REMEDIATION === 'true') {
  try {
    const attack = await contract.evaluate({
      request_id: 'live-attack-before-remediation',
      action: 'revoke-credential',
      resource: 'credential:security-api',
      purpose: 'incident-remediation',
      host: 'attacker.example',
      fields: ['incident_id', 'credential_id', 'reason', 'api_key'],
    });
    observePolicy(attack);
    const safe = await contract.evaluate({
      request_id: 'live-safe-after-attack',
      action: 'revoke-credential',
      resource: 'credential:security-api',
      purpose: 'incident-remediation',
      host: 'postman-echo.com',
      fields: ['incident_id', 'credential_id', 'reason'],
    });
    observePolicy(safe);
    if (attack.decision !== 'DENY' || safe.decision !== 'ALLOW' || !safe.policy_version || !safe.policy_hash) {
      record('LIVE-SAFE-AFTER-ATTACK', 'DENY -> ALLOW -> accepted execution -> independent VERIFIED read-back', `${attack.decision} -> ${safe.decision}`, 'FAIL');
    } else {
      const remediation = await contract.remediate({
        request_id: safe.request_id,
        action: 'revoke-credential',
        resource: 'credential:security-api',
        purpose: 'incident-remediation',
        fields: ['incident_id', 'credential_id', 'reason'],
        policy_version: safe.policy_version,
        policy_hash: safe.policy_hash,
      }, executorDid);
      if (!remediation.operation_id) {
        record('LIVE-SAFE-AFTER-ATTACK', 'DENY -> ALLOW -> accepted execution -> independent VERIFIED read-back', `${attack.decision} -> ${safe.decision} -> ${remediation.status}`, 'FAIL', 'External acceptance did not return an operation id; completion cannot be verified.');
      } else {
        const verification = await contract.verifyRemediation({
          request_id: remediation.request_id,
          operation_id: remediation.operation_id,
          expected_state: 'REVOKED',
        });
        const actual = `${attack.decision} -> ${safe.decision} -> ${remediation.status} -> ${verification.status}${verification.observed_state ? ` (${verification.observed_state})` : ''}`;
        record(
          'LIVE-SAFE-AFTER-ATTACK',
          'DENY -> ALLOW -> accepted execution -> independent VERIFIED read-back',
          actual,
          verification.status === 'VERIFIED' && verification.observed_state === 'REVOKED' ? 'PASS' : 'FAIL',
        );
      }
    }
  } catch (error) {
    record('LIVE-SAFE-AFTER-ATTACK', 'DENY -> ALLOW -> accepted execution -> independent VERIFIED read-back', null, 'FAIL', sanitizeEvidenceError(error));
  }
} else {
  record(
    'LIVE-SAFE-AFTER-ATTACK',
    'DENY -> ALLOW -> accepted execution -> independent VERIFIED read-back',
    null,
    'NOT_RUN',
    'Set EVIDENCE_RUN_REMEDIATION=true only after seeding both remediation and independent verification endpoints in the private map and granting the Executor functions.',
  );
}

const evidence: EvidenceBundle = {
  generatedAt: new Date().toISOString(), network: config.network, sdkVersion: '5.2.0', tenantDid, agentDid, executorDid,
  contractId: identity.contractId, contractVersion: identity.contractVersion, wasmSha256: await wasmHash(),
  policyVersion: observedPolicyVersion, policyHash: observedPolicyHash,
  delegation: {
    proposal: evidenceDelegation(proposalDelegationStatus),
    executor: evidenceDelegation(executorDelegationStatus),
  },
  scenarios,
};
const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
assertNoSecretLeak(serialized, [config.apiKey, config.agentApiKey, config.executorApiKey, process.env.EVIDENCE_SENTINEL_SECRET, process.env.SECURITY_API_KEY, process.env.AI_API_KEY, config.gatewayServiceToken, config.remediationCapabilityKey]);
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, serialized, 'utf8');
console.info(JSON.stringify({ outputPath, proposalAgentDid: agentDid, protectedExecutorDid: executorDid, proposalEffectiveAccess: proposalDelegationStatus.effectiveState, executorEffectiveAccess: executorDelegationStatus.effectiveState, policyVersion: observedPolicyVersion, policyHash: observedPolicyHash, pass: scenarios.filter((item) => item.status === 'PASS').length, fail: scenarios.filter((item) => item.status === 'FAIL').length, notRun: scenarios.filter((item) => item.status === 'NOT_RUN').length }, null, 2));
if (scenarios.some((item) => item.status === 'FAIL')) process.exitCode = 1;