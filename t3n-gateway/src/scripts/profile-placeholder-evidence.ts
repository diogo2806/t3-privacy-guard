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

const ID = 'LIVE-PROFILE-PLACEHOLDER-RESOLUTION';
const EXPECTED = 'ALLOW -> protected notify-security -> VERIFIED DELIVERED with recipient_resolved=true and no recipient plaintext returned';

if (process.env.EVIDENCE_RUN_PROFILE_PLACEHOLDER !== 'true') process.exit(0);

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

  const decision = await contract.evaluate({
    request_id: 'live-private-placeholder-notify',
    action: 'notify-security',
    resource: 'incident:synthetic',
    purpose: 'incident-notification',
    host,
    fields: ['incident_id', 'severity', 'summary'],
    private_refs: ['verified_email'],
  });
  if (decision.decision !== 'ALLOW' || !decision.policy_version || !decision.policy_hash) {
    throw new Error(`Notification policy was ${decision.decision}; ALLOW with versioned policy metadata is required`);
  }

  const remediation = await contract.remediate({
    request_id: decision.request_id,
    action: 'notify-security',
    resource: 'incident:synthetic',
    purpose: 'incident-notification',
    approved_host: host,
    fields: ['incident_id', 'severity', 'summary'],
    normal_payload: {
      incident_id: 'inc-demo-001',
      severity: 'critical',
      summary: 'synthetic security incident',
    },
    private_refs: ['verified_email'],
    policy_version: decision.policy_version,
    policy_hash: decision.policy_hash,
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
      ? 'Controlled read-back confirmed delivery and private recipient resolution. Only the boolean resolution assertion is persisted; recipient plaintext and placeholder literals are not returned.'
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
]);
await writeFile(outputPath, serialized, 'utf8');
if (result.status === 'FAIL') process.exitCode = 1;
