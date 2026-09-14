import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getContractVersion, getNodeUrl } from '@terminal3/t3n-sdk';
import { AgentSession } from '../agent/agent-session.js';
import { DelegationService, EXECUTOR_DELEGATION_REQUIREMENTS } from '../agent/delegation-service.js';
import { ExecutorSession } from '../agent/executor-session.js';
import { readGatewayConfig } from '../config/env.js';
import { buildDelegatedExecutionRequest, PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import { assertNoSecretLeak, sanitizeEvidenceError } from '../evidence/leak-detector.js';
import { authorizationPublicKeyFingerprint } from '../security/remediation-authorization.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

interface HumanProofEvidence {
  generatedAt: string;
  network: string;
  contractId: string;
  contractVersion: string;
  executorDid: string;
  executorMemberState: string;
  executorEffectiveState: string;
  verificationKeyFingerprint: string;
  scenario: {
    id: 'LIVE-EXECUTOR-REQUIRES-HUMAN-PROOF';
    expected: string;
    actual: 'REJECTED_BY_T3N_WASM' | 'ACCEPTED_UNEXPECTEDLY';
    status: 'PASS' | 'FAIL';
    detail: string;
  };
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDir, '../../..');
const outputPath = resolve(process.env.EVIDENCE_HUMAN_PROOF_OUTPUT ?? resolve(repositoryRoot, 'docs/evidence/human-proof-testnet.json'));
const config = readGatewayConfig();
if (config.network !== 'testnet' && process.env.EVIDENCE_ALLOW_PRODUCTION !== 'true') {
  throw new Error('Human-proof adversarial evidence is restricted to testnet unless EVIDENCE_ALLOW_PRODUCTION=true is explicitly set');
}
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required to obtain current policy provenance for the evidence request');
if (!config.executorApiKey) throw new Error('T3N_EXECUTOR_API_KEY is required for direct protected-executor evidence');

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const tenantSession = new T3nSession(config, trustFloorStore);
const agentSession = new AgentSession(config, trustFloorStore);
const executorSession = new ExecutorSession(config, trustFloorStore);
const executorDelegation = new DelegationService(tenantSession, executorSession, EXECUTOR_DELEGATION_REQUIREMENTS);
const contract = new PrivacyGuardContractService(config, tenantSession, agentSession, executorSession);

await Promise.all([tenantSession.connect(), agentSession.connect(), executorSession.connect()]);
const tenantDid = tenantSession.getTenantDid();
const executorDid = executorSession.getExecutorDid();
const contractId = `z:${tenantDid.slice('did:t3n:'.length)}:${config.contractTail}`;
const contractVersion = await getContractVersion(getNodeUrl(), contractId);
const delegation = await executorDelegation.status(contractId);
if (delegation.memberState !== 'ACTIVE' || delegation.effectiveState !== 'ACTIVE') {
  throw new Error(`Protected Executor must be ACTIVE/Confirmed before testing the human-proof boundary; member=${delegation.memberState}; effective=${delegation.effectiveState}`);
}

const approvedHost = (() => {
  const configured = process.env.SECURITY_API_URL?.trim();
  if (!configured) return 'postman-echo.com';
  const parsed = new URL(configured);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port || !parsed.hostname) {
    throw new Error('SECURITY_API_URL must be HTTPS with a canonical hostname and no credentials or explicit port');
  }
  return parsed.hostname.toLowerCase();
})();

const decision = await contract.evaluate({
  request_id: 'live-executor-proof-policy',
  action: 'revoke-credential',
  resource: 'credential:security-api',
  purpose: 'incident-remediation',
  host: approvedHost,
  fields: ['incident_id', 'credential_id', 'reason'],
  private_refs: [],
});
if (decision.decision !== 'ALLOW' || !decision.policy_version || !decision.policy_hash) {
  throw new Error(`Human-proof evidence requires a live ALLOW policy decision; observed=${decision.decision}`);
}

const expected = 'ACTIVE Protected Executor calling execute-remediation directly without a signed one-time human-authorization proof is rejected by T3N/WASM before protected egress';
let actual: HumanProofEvidence['scenario']['actual'] = 'ACCEPTED_UNEXPECTEDLY';
let status: HumanProofEvidence['scenario']['status'] = 'FAIL';
let detail = 'Direct Protected Executor call unexpectedly returned successfully';
try {
  await executorSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
    tenantDid,
    contractId,
    contractVersion,
    'execute-remediation',
    {
      incident_id: 'live-human-proof-incident',
      action_id: 'live-human-proof-action',
      decision_id: 'live-human-proof-decision',
      request_id: 'live-human-proof-direct-executor',
      agent_did: agentSession.getAgentDid(),
      executor_did: executorDid,
      action: 'revoke-credential',
      resource: 'credential:security-api',
      purpose: 'incident-remediation',
      approved_host: approvedHost,
      fields: ['incident_id', 'credential_id', 'reason'],
      normal_payload: {
        incident_id: 'inc-demo-001',
        credential_id: 'cred-demo-001',
        reason: 'suspected compromise',
      },
      private_refs: [],
      policy_version: decision.policy_version,
      policy_hash: decision.policy_hash,
      authorization_proof: '',
    },
  ));
} catch (error) {
  actual = 'REJECTED_BY_T3N_WASM';
  status = 'PASS';
  const sanitized = sanitizeEvidenceError(error);
  detail = sanitized.toLowerCase().includes('authorization proof')
    ? 'T3N/WASM explicitly rejected the direct Executor call because the one-time authorization proof was missing.'
    : `T3N rejected the call while the Executor delegation was independently confirmed ACTIVE. Sanitized contract error: ${sanitized}`;
}

const evidence: HumanProofEvidence = {
  generatedAt: new Date().toISOString(),
  network: config.network,
  contractId,
  contractVersion,
  executorDid,
  executorMemberState: delegation.memberState,
  executorEffectiveState: delegation.effectiveState,
  verificationKeyFingerprint: authorizationPublicKeyFingerprint(config.remediationAuthorizationPublicKeySpki),
  scenario: {
    id: 'LIVE-EXECUTOR-REQUIRES-HUMAN-PROOF',
    expected,
    actual,
    status,
    detail,
  },
};
const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
assertNoSecretLeak(serialized, [
  config.apiKey,
  config.agentApiKey,
  config.executorApiKey,
  config.gatewayServiceToken,
  process.env.SECURITY_API_KEY,
  process.env.AI_API_KEY,
  process.env.REMEDIATION_AUTH_PRIVATE_KEY_PKCS8,
]);
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, serialized, 'utf8');
console.info(JSON.stringify({ outputPath, status, contractId, contractVersion, executorDid, verificationKeyFingerprint: evidence.verificationKeyFingerprint }, null, 2));
if (status === 'FAIL') process.exitCode = 1;
