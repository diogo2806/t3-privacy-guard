import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentSession } from '../agent/agent-session.js';
import { DelegationService } from '../agent/delegation-service.js';
import { readGatewayConfig } from '../config/env.js';
import { PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import { assertNoSecretLeak, sanitizeEvidenceError } from '../evidence/leak-detector.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

type EvidenceStatus = 'PASS' | 'FAIL' | 'NOT_RUN';
interface ScenarioResult { id: string; layer: 'T3N_TESTNET'; expected: string; actual: string | null; status: EvidenceStatus; detail?: string; }
interface EvidenceBundle {
  generatedAt: string; network: string; sdkVersion: '5.2.0'; tenantDid: string; agentDid: string;
  contractId: string; contractVersion: string; wasmSha256: string | null; scenarios: ScenarioResult[];
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

const config = readGatewayConfig();
if (config.network !== 'testnet' && process.env.EVIDENCE_ALLOW_PRODUCTION !== 'true') throw new Error('Adversarial evidence runner is restricted to testnet unless EVIDENCE_ALLOW_PRODUCTION=true is explicitly set');
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required for testnet evidence');

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const tenantSession = new T3nSession(config, trustFloorStore);
const agentSession = new AgentSession(config, trustFloorStore);
const delegation = new DelegationService(tenantSession, agentSession);
const contract = new PrivacyGuardContractService(config, tenantSession, agentSession);
const scenarios: ScenarioResult[] = [];

function record(id: string, expected: string, actual: string | null, status: EvidenceStatus, detail?: string): void {
  scenarios.push({ id, layer: 'T3N_TESTNET', expected, actual, status, detail });
}
async function wasmHash(): Promise<string | null> {
  try { return createHash('sha256').update(await readFile(wasmPath)).digest('hex'); } catch { return null; }
}
async function grantFull(contractId: string, version: string): Promise<void> {
  await delegation.grant({
    contractId,
    versionReq: version,
    functions: ['evaluate-action', 'execute-remediation', 'verify-remediation'],
    scopes: ['incident_id', 'credential_id', 'reason'],
    allowedHosts: configuredEgressHosts(),
  });
}
async function decisionScenario(id: string, expected: 'ALLOW' | 'REDACT' | 'DENY', input: Parameters<PrivacyGuardContractService['evaluate']>[0]): Promise<void> {
  try {
    const result = await contract.evaluate(input);
    record(id, expected, result.decision, result.decision === expected ? 'PASS' : 'FAIL', result.reason_code);
  } catch (error) { record(id, expected, null, 'FAIL', sanitizeEvidenceError(error)); }
}
function isAuthorizationRejection(message: string): boolean {
  return /(egress|denied|not[ -]?authori[sz]ed|authori[sz]ation|delegat|permission|function.*allow|grant)/i.test(message);
}
async function expectProtectedEgressRejected(id: string, expected: string, requestId: string): Promise<void> {
  try {
    const result = await contract.remediate({
      request_id: requestId,
      action: 'revoke-credential',
      resource: 'credential:security-api',
      purpose: 'incident-remediation',
      fields: ['incident_id', 'credential_id', 'reason'],
    });
    record(id, expected, result.status, 'FAIL', 'Protected egress unexpectedly reached the acceptance state');
  } catch (error) {
    const detail = sanitizeEvidenceError(error);
    record(id, expected, 'REJECTED', isAuthorizationRejection(detail) ? 'PASS' : 'FAIL', detail);
  }
}

await tenantSession.connect();
await agentSession.connect();
const identity = await contract.identity();
const tenantDid = tenantSession.getTenantDid();
const agentDid = agentSession.getAgentDid();
record('LIVE-IDENTITY-SEPARATION', 'tenant DID differs from agent DID', tenantDid === agentDid ? 'same DID' : 'different DIDs', tenantDid !== agentDid ? 'PASS' : 'FAIL');
await grantFull(identity.contractId, identity.contractVersion);

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
  'LIVE-PROFILE-PLACEHOLDER-RESOLUTION',
  'verified_email resolved by T3N profile placeholder only during protected egress',
  null,
  'NOT_RUN',
  'Requires a dedicated synthetic T3N profile with verified email and compatible delegated scope/user context. Local mapping tests do not count as live resolution proof.',
);

if (process.env.EVIDENCE_RUN_EGRESS_NEGATIVES === 'true') {
  try {
    await delegation.grant({ contractId: identity.contractId, versionReq: identity.contractVersion, functions: ['evaluate-action'], scopes: ['incident_id', 'credential_id', 'reason'], allowedHosts: [] });
    await expectProtectedEgressRejected('LIVE-FUNCTION-OUTSIDE-DELEGATION', 'protected egress rejected when execute-remediation is not granted', 'live-function-deny');
    await grantFull(identity.contractId, identity.contractVersion);
    await delegation.revoke(identity.contractId);
    await expectProtectedEgressRejected('LIVE-REVOKED-AGENT', 'protected egress rejected after grant revocation', 'live-revoked-deny');
  } finally { await grantFull(identity.contractId, identity.contractVersion); }
} else {
  record('LIVE-FUNCTION-OUTSIDE-DELEGATION', 'protected egress rejected when execute-remediation is not granted', null, 'NOT_RUN', 'Set EVIDENCE_RUN_EGRESS_NEGATIVES=true only after the private remediation map has been seeded.');
  record('LIVE-REVOKED-AGENT', 'protected egress rejected after grant revocation', null, 'NOT_RUN', 'Set EVIDENCE_RUN_EGRESS_NEGATIVES=true only after the private remediation map has been seeded.');
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
    if (attack.decision !== 'DENY') {
      record('LIVE-SAFE-AFTER-ATTACK', 'DENY -> accepted execution -> independent VERIFIED read-back', attack.decision, 'FAIL');
    } else {
      const remediation = await contract.remediate({
        request_id: 'live-safe-after-attack',
        action: 'revoke-credential',
        resource: 'credential:security-api',
        purpose: 'incident-remediation',
        fields: ['incident_id', 'credential_id', 'reason'],
      });
      if (!remediation.operation_id) {
        record('LIVE-SAFE-AFTER-ATTACK', 'DENY -> accepted execution -> independent VERIFIED read-back', `${attack.decision} -> ${remediation.status}`, 'FAIL', 'External acceptance did not return an operation id; completion cannot be verified.');
      } else {
        const verification = await contract.verifyRemediation({
          request_id: remediation.request_id,
          operation_id: remediation.operation_id,
          expected_state: 'REVOKED',
        });
        const actual = `${attack.decision} -> ${remediation.status} -> ${verification.status}${verification.observed_state ? ` (${verification.observed_state})` : ''}`;
        record(
          'LIVE-SAFE-AFTER-ATTACK',
          'DENY -> accepted execution -> independent VERIFIED read-back',
          actual,
          verification.status === 'VERIFIED' && verification.observed_state === 'REVOKED' ? 'PASS' : 'FAIL',
        );
      }
    }
  } catch (error) {
    record('LIVE-SAFE-AFTER-ATTACK', 'DENY -> accepted execution -> independent VERIFIED read-back', null, 'FAIL', sanitizeEvidenceError(error));
  }
} else {
  record(
    'LIVE-SAFE-AFTER-ATTACK',
    'DENY -> accepted execution -> independent VERIFIED read-back',
    null,
    'NOT_RUN',
    'Set EVIDENCE_RUN_REMEDIATION=true only after seeding both remediation and independent verification endpoints in the private map and granting both contract functions.',
  );
}

const evidence: EvidenceBundle = { generatedAt: new Date().toISOString(), network: config.network, sdkVersion: '5.2.0', tenantDid, agentDid, contractId: identity.contractId, contractVersion: identity.contractVersion, wasmSha256: await wasmHash(), scenarios };
const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
assertNoSecretLeak(serialized, [config.apiKey, config.agentApiKey, process.env.EVIDENCE_SENTINEL_SECRET, process.env.SECURITY_API_KEY, process.env.AI_API_KEY, config.gatewayServiceToken, config.remediationCapabilityKey]);
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, serialized, 'utf8');
console.info(JSON.stringify({ outputPath, pass: scenarios.filter((item) => item.status === 'PASS').length, fail: scenarios.filter((item) => item.status === 'FAIL').length, notRun: scenarios.filter((item) => item.status === 'NOT_RUN').length }, null, 2));
if (scenarios.some((item) => item.status === 'FAIL')) process.exitCode = 1;
