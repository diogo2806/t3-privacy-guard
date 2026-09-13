import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { AgentCardRegistry } from '../agent/agent-card.js';
import { AgentSession } from '../agent/agent-session.js';
import { DelegationService } from '../agent/delegation-service.js';
import { ExecutorSession } from '../agent/executor-session.js';
import { readGatewayConfig } from '../config/env.js';
import { PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import { assertEvidenceMatchesDeployment, assertManifestIdentity, sha256File, type DeploymentManifest, type TestnetEvidenceIdentity } from '../evidence/deployment-manifest.js';
import { assertNoSecretLeak } from '../evidence/leak-detector.js';
import { canonicalizeOperationalPolicy } from '../policy/policy-document.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const gatewayRoot = resolve(scriptDir, '../..');
const repositoryRoot = resolve(gatewayRoot, '..');
const evidenceDir = resolve(repositoryRoot, 'docs/evidence');
const wasmPath = resolve(process.env.T3N_CONTRACT_WASM_PATH ?? resolve(repositoryRoot, 'contracts/privacy-guard/target/wasm32-wasip2/release/privacy_guard_contract.wasm'));
const policyPath = resolve(gatewayRoot, process.env.T3N_POLICY_FILE ?? 'policy/privacy-guard-policy.json');
const manifestPath = resolve(process.env.EVIDENCE_DEPLOYMENT_MANIFEST ?? resolve(evidenceDir, 'deployment-manifest.json'));
const testnetPath = resolve(process.env.EVIDENCE_OUTPUT ?? resolve(evidenceDir, 'testnet-run.json'));

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
if (config.network !== 'testnet' && process.env.EVIDENCE_ALLOW_PRODUCTION !== 'true') {
  throw new Error('Live evidence orchestration is restricted to testnet unless EVIDENCE_ALLOW_PRODUCTION=true');
}
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required for live evidence');
if (!config.executorApiKey) throw new Error('T3N_EXECUTOR_API_KEY is required for live evidence');

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const tenantSession = new T3nSession(config, trustFloorStore);
const agentSession = new AgentSession(config, trustFloorStore);
const executorSession = new ExecutorSession(config, trustFloorStore);
const agentCardRegistry = new AgentCardRegistry(agentSession);
const proposalDelegation = new DelegationService(tenantSession, agentSession);
const executorDelegation = new DelegationService(tenantSession, executorSession);
const contract = new PrivacyGuardContractService(config, tenantSession, agentSession, executorSession);
await tenantSession.connect();
await Promise.all([agentSession.connect(), executorSession.connect()]);

const tenantStatus = tenantSession.getStatus();
const agentStatus = agentSession.getStatus();
const executorStatus = executorSession.getExecutorStatus();
const persistedTrustFloor = await trustFloorStore.get(config.network);
if (!tenantStatus.trustAnchorVerified || !agentStatus.trustAnchorVerified || !executorStatus.trustAnchorVerified || !persistedTrustFloor) {
  throw new Error('Live evidence requires verified T3N trust anchors and a persisted rollback floor for all principals');
}
if (
  tenantStatus.trustManifestVersion === null
  || agentStatus.trustManifestVersion === null
  || executorStatus.trustManifestVersion === null
  || tenantStatus.trustManifestVersion > persistedTrustFloor.version
  || agentStatus.trustManifestVersion > persistedTrustFloor.version
  || executorStatus.trustManifestVersion > persistedTrustFloor.version
) {
  throw new Error('Persisted T3N trust manifest floor is inconsistent with authenticated sessions');
}

const tenantDid = tenantSession.getTenantDid();
const agentDid = agentSession.getAgentDid();
const executorDid = executorSession.getExecutorDid();
if (new Set([tenantDid, agentDid, executorDid]).size !== 3) throw new Error('Tenant, proposal Agent and protected Executor DIDs must be different');
const agentRegistration = await agentCardRegistry.verify();
if (agentRegistration.agentDid && agentRegistration.agentDid !== agentDid) throw new Error('Agent Card verification DID differs from the authenticated Proposal Agent DID');
const wasmSha256 = await sha256File(wasmPath);
const policySource = JSON.parse(await readFile(policyPath, 'utf8')) as unknown;
const policy = canonicalizeOperationalPolicy(policySource);

let contractId: string;
let contractVersion: string;
let numericContractId: number | null = null;
try {
  const identity = await contract.identity();
  contractId = identity.contractId;
  contractVersion = identity.contractVersion;
  if (contractVersion !== config.contractVersion) {
    throw new Error(`Resolved contract version ${contractVersion} does not match configured ${config.contractVersion}`);
  }
  const configuredNumeric = Number(process.env.T3N_CONTRACT_NUMERIC_ID);
  numericContractId = Number.isInteger(configuredNumeric) && configuredNumeric > 0 ? configuredNumeric : null;
} catch {
  const tenant = new TenantClient({ t3n: tenantSession.getClient(), baseUrl: getNodeUrl(), tenantDid });
  const result = await tenant.contracts.register({ tail: config.contractTail, version: config.contractVersion, wasm: await readFile(wasmPath) });
  numericContractId = result.contract_id;
  const identity = await contract.identity();
  contractId = identity.contractId;
  contractVersion = identity.contractVersion;
}
if (!numericContractId) throw new Error('T3N_CONTRACT_NUMERIC_ID is required for an existing contract so the versioned policy map can authorize this contract');

const policySetup = spawnSync('npm', ['run', 'contract:setup-policy'], {
  cwd: gatewayRoot,
  env: { ...process.env, T3N_CONTRACT_NUMERIC_ID: String(numericContractId), T3N_POLICY_FILE: policyPath },
  stdio: 'inherit',
});
if (policySetup.status !== 0) throw new Error('Versioned T3N operational policy setup/read-back failed');

const manifest: DeploymentManifest = {
  source: 'T3N_TESTNET',
  generatedAt: new Date().toISOString(),
  network: config.network,
  sdkVersion: '5.2.0',
  tenantDid,
  agentDid,
  executorDid,
  agentRegistrationState: agentRegistration.state,
  agentCardUri: agentRegistration.cardUri,
  agentCardSha256: agentRegistration.cardSha256,
  agentCardVerifiedAt: agentRegistration.verifiedAt,
  agentCardServices: agentRegistration.services,
  contractId,
  numericContractId,
  contractVersion,
  wasmSha256,
  policyVersion: policy.document.version,
  policyHash: policy.hash,
  trustAnchorVerified: true,
  trustManifestFloorPersisted: true,
  trustManifestVersion: persistedTrustFloor.version,
};
assertManifestIdentity(manifest);
if (manifest.contractVersion !== config.contractVersion) throw new Error('Deployment manifest contract version differs from configured version');

const sensitiveValues = [
  config.apiKey,
  config.agentApiKey,
  config.executorApiKey,
  process.env.SECURITY_API_KEY,
  process.env.EVIDENCE_SENTINEL_SECRET,
  process.env.AI_API_KEY,
  config.gatewayServiceToken,
  config.remediationCapabilityKey,
];
const serializedManifest = `${JSON.stringify(manifest, null, 2)}\n`;
assertNoSecretLeak(serializedManifest, sensitiveValues);
await mkdir(dirname(manifestPath), { recursive: true });
await writeFile(manifestPath, serializedManifest, 'utf8');

if (process.env.EVIDENCE_PREPARE_EGRESS === 'true') {
  if (!process.env.SECURITY_API_URL?.startsWith('https://')) {
    throw new Error('SECURITY_API_URL is required when preparing verifiable remediation evidence');
  }
  if (!process.env.SECURITY_VERIFICATION_URL?.startsWith('https://')) {
    throw new Error('SECURITY_VERIFICATION_URL is required when preparing verifiable remediation evidence');
  }
  const setup = spawnSync('npm', ['run', 'contract:setup-remediation'], {
    cwd: gatewayRoot,
    env: { ...process.env, T3N_CONTRACT_NUMERIC_ID: String(numericContractId) },
    stdio: 'inherit',
  });
  if (setup.status !== 0) throw new Error('Private remediation map setup failed');
}

await proposalDelegation.grant({
  contractId,
  versionReq: contractVersion,
  functions: ['evaluate-action'],
  scopes: ['incident_id', 'credential_id', 'reason'],
  allowedHosts: [],
});
await executorDelegation.grant({
  contractId,
  versionReq: contractVersion,
  functions: ['execute-remediation', 'verify-remediation'],
  scopes: ['incident_id', 'credential_id', 'reason'],
  allowedHosts: configuredEgressHosts(),
});

const run = spawnSync('npm', ['run', 'evidence:testnet'], {
  cwd: gatewayRoot,
  env: { ...process.env, EVIDENCE_OUTPUT: testnetPath, T3N_CONTRACT_WASM_PATH: wasmPath },
  stdio: 'inherit',
});
if (run.status !== 0) throw new Error('T3N testnet evidence runner reported a failure');

const evidence = JSON.parse(await readFile(testnetPath, 'utf8')) as TestnetEvidenceIdentity & { scenarios?: Array<{ status?: string }> };
assertEvidenceMatchesDeployment(manifest, evidence);
if (evidence.scenarios?.some((scenario) => scenario.status === 'FAIL')) throw new Error('T3N testnet evidence contains FAIL scenarios');

const finalSerialized = await readFile(testnetPath, 'utf8');
assertNoSecretLeak(finalSerialized, sensitiveValues);
console.info(JSON.stringify({
  manifestPath,
  testnetPath,
  contractId,
  contractVersion,
  wasmSha256,
  policyVersion: policy.document.version,
  policyHash: policy.hash,
  proposalAgentDid: agentDid,
  protectedExecutorDid: executorDid,
  agentRegistrationState: agentRegistration.state,
  agentCardSha256: agentRegistration.cardSha256,
  trustManifestVersion: persistedTrustFloor.version,
  trustFloorPersisted: true,
  evidenceLinked: true,
}, null, 2));
