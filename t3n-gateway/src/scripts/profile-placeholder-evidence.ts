import { readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentSession } from '../agent/agent-session.js';
import { ExecutorSession } from '../agent/executor-session.js';
import { readGatewayConfig } from '../config/env.js';
import { PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import { assertNoSecretLeak, sanitizeEvidenceError } from '../evidence/leak-detector.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

interface ScenarioResult {
  id: string;
  layer: 'T3N_TESTNET';
  expected: string;
  actual: string | null;
  status: 'PASS' | 'FAIL' | 'NOT_RUN';
  detail?: string;
}

interface TestnetEvidence {
  scenarios: ScenarioResult[];
  [key: string]: unknown;
}

interface AuthorizationClaims {
  incidentId: string;
  actionId: string;
  requestId: string;
  decisionId: string;
  action: string;
  resource: string;
  purpose: string;
  approvedHost: string;
  policyVersion: string;
  policyHash: string;
  executorDid: string;
}

const ID = 'LIVE-PROFILE-PLACEHOLDER-RESOLUTION';
const EXPECTED = 'human-authorized ALLOW -> protected notify-security -> VERIFIED DELIVERED with recipient_resolved=true and no recipient plaintext returned';
const FIELDS = ['incident_id', 'severity', 'summary'];
const PRIVATE_REFS = ['verified_email'];
const NORMAL_PAYLOAD = {
  incident_id: 'inc-demo-001',
  severity: 'critical',
  summary: 'synthetic security incident',
};

if (process.env.EVIDENCE_RUN_PROFILE_PLACEHOLDER !== 'true') process.exit(0);

const authorizationProof = process.env.EVIDENCE_NOTIFICATION_AUTHORIZATION_PROOF?.trim();
if (!authorizationProof) {
  throw new Error('EVIDENCE_NOTIFICATION_AUTHORIZATION_PROOF is required; generate it through the authenticated backend human-authorization flow for the fixed synthetic notify-security request');
}

function decodeClaims(token: string): AuthorizationClaims {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'v2') throw new Error('Evidence notification authorization proof must use v2');
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as AuthorizationClaims;
  } catch {
    throw new Error('Evidence notification authorization proof payload is invalid');
  }
}

const claims = decodeClaims(authorizationProof);
if (claims.action !== 'notify-security' || claims.purpose !== 'incident-notification') {
  throw new Error('Evidence notification authorization proof is not bound to notify-security / incident-notification');
}
if (!claims.incidentId || !claims.actionId || !claims.requestId || !claims.decisionId || !claims.resource
  || !claims.approvedHost || !claims.policyVersion || !claims.policyHash || !claims.executorDid) {
  throw new Error('Evidence notification authorization proof is missing required bound claims');
}

const config = readGatewayConfig();
if (config.network !== 'testnet') throw new Error('Private placeholder resolution evidence is testnet-only');
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required for private placeholder evidence');
if (!config.executorApiKey) throw new Error('T3N_EXECUTOR_API_KEY is required for private placeholder evidence');
if (!process.env.SECURITY_API_URL?.trim() || !process.env.SECURITY_VERIFICATION_URL?.trim()) {
  throw new Error('SECURITY_API_URL and SECURITY_VERIFICATION_URL are required for private placeholder evidence');
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(scriptDir, '../../..');
const outputPath = resolve(process.env.EVIDENCE_OUTPUT ?? resolve(repositoryRoot, 'docs/evidence/testnet-run.json'));
const evidence = JSON.parse(await readFile(outputPath, 'utf8')) as TestnetEvidence;
if (!Array.isArray(evidence.scenarios)) throw new Error('Testnet evidence does not contain a scenarios array');

function executionHost(): string {
  const parsed = new URL(process.env.SECURITY_API_URL!);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port) {
    throw new Error('SECURITY_API_URL must be canonical HTTPS without credentials or explicit port');
  }
  return parsed.hostname.toLowerCase();
}

function replaceScenario(result: ScenarioResult): void {
  const index = evidence.scenarios.findIndex((scenario) => scenario.id === ID);
  if (index >= 0) evidence.scenarios[index] = result;
  else evidence.scenarios.push(result);
}

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const tenantSession = new T3nSession(config, trustFloorStore);
const agentSession = new AgentSession(config, trustFloorStore);
const executorSession = new ExecutorSession(config, trustFloorStore);
const contract = new PrivacyGuardContractService(config, tenantSession, agentSession, executorSession);

let result: ScenarioResult;
try {
  await tenantSession.connect();
  await Promise.all([agentSession.connect(), executorSession.connect()]);
  const executorDid = executorSession.getExecutorDid();
  const host = executionHost();
  if (claims.executorDid !== executorDid) throw new Error('Authorization proof is bound to a different Protected Executor');
  if (claims.approvedHost.toLowerCase() !== host) throw new Error('Authorization proof is bound to a different approved execution host');

  const decision = await contract.evaluate({
    request_id: claims.requestId,
    action: 'notify-security',
    resource: claims.resource,
    purpose: 'incident-notification',
    host,
    fields: FIELDS,
    private_refs: PRIVATE_REFS,
  });
  if (decision.decision !== 'ALLOW' || !decision.policy_version || !decision.policy_hash) {
    throw new Error(`Notification policy was ${decision.decision}; ALLOW with versioned policy metadata is required`);
  }
  if (decision.policy_version !== claims.policyVersion || decision.policy_hash !== claims.policyHash) {
    throw new Error('Authorization proof policy metadata no longer matches the active notification policy');
  }

  const remediation = await contract.remediate({
    incident_id: claims.incidentId,
    action_id: claims.actionId,
    decision_id: claims.decisionId,
    request_id: claims.requestId,
    action: 'notify-security',
    resource: claims.resource,
    purpose: 'incident-notification',
    approved_host: host,
    fields: FIELDS,
    normal_payload: NORMAL_PAYLOAD,
    private_refs: PRIVATE_REFS,
    policy_version: claims.policyVersion,
    policy_hash: claims.policyHash,
    executor_did: executorDid,
    authorization_proof: authorizationProof,
  }, executorDid);
  if (!remediation.operation_id) throw new Error('Controlled notification endpoint did not return an operation id');

  const verification = await contract.verifyRemediation({
    request_id: remediation.request_id,
    operation_id: remediation.operation_id,
    action: 'notify-security',
    expected_state: 'DELIVERED',
  });
  const passed = verification.status === 'VERIFIED'
    && verification.observed_state === 'DELIVERED'
    && verification.recipient_resolved === true;

  result = {
    id: ID,
    layer: 'T3N_TESTNET',
    expected: EXPECTED,
    actual: `${decision.decision} -> ${remediation.status} -> ${verification.status} (${verification.observed_state ?? 'NO_STATE'}); recipient_resolved=${verification.recipient_resolved === true}`,
    status: passed ? 'PASS' : 'FAIL',
    detail: passed
      ? 'Controlled read-back confirmed delivery and private recipient resolution after the signed human-authorization proof passed the T3N/WASM boundary. Only the boolean resolution assertion is persisted.'
      : 'Independent read-back did not confirm both DELIVERED and recipient_resolved=true.',
  };
} catch (error) {
  result = {
    id: ID,
    layer: 'T3N_TESTNET',
    expected: EXPECTED,
    actual: null,
    status: 'FAIL',
    detail: sanitizeEvidenceError(error),
  };
}

replaceScenario(result);
const serialized = `${JSON.stringify(evidence, null, 2)}\n`;
if (serialized.includes('{{profile.')) throw new Error('Evidence artifact contains a forbidden raw profile placeholder');
assertNoSecretLeak(serialized, [
  config.apiKey,
  config.agentApiKey,
  config.executorApiKey,
  process.env.SECURITY_API_KEY,
  process.env.AI_API_KEY,
  config.gatewayServiceToken,
  config.remediationCapabilityKey,
  authorizationProof,
]);
await writeFile(outputPath, serialized, 'utf8');
if (result.status === 'FAIL') process.exitCode = 1;
