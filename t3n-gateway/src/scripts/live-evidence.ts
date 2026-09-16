import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentCardRegistry } from '../agent/agent-card.js';
import { AgentSession } from '../agent/agent-session.js';
import {
  DelegationService,
  EXECUTOR_DELEGATION_REQUIREMENTS,
  PROPOSAL_DELEGATION_REQUIREMENTS,
  type DelegationStatus,
} from '../agent/delegation-service.js';
import { ExecutorSession } from '../agent/executor-session.js';
import { readGatewayConfig } from '../config/env.js';
import { PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import { assertEvidenceMatchesDeployment, assertManifestIdentity, sha256File, type DeploymentManifest, type TestnetEvidenceIdentity } from '../evidence/deployment-manifest.js';
import { assertNoSecretLeak } from '../evidence/leak-detector.js';
import { resolveSourceRevision } from '../evidence/source-revision.js';
import { canonicalizeOperationalPolicy } from '../policy/policy-document.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const gatewayRoot = resolve(scriptDir, '../..');
const repositoryRoot = resolve(gatewayRoot, '..');
const productionRuntime = process.env.NODE_ENV === 'production';
const evidenceDir = resolve(
  process.env.EVIDENCE_RUNTIME_DIR?.trim()
    || (productionRuntime ? '/data/evidence' : resolve(repositoryRoot, 'docs/evidence')),
);
const wasmPath = resolve(process.env.T3N_CONTRACT_WASM_PATH?.trim() || resolve(repositoryRoot, 'contracts/privacy-guard/target/wasm32-wasip2/release/privacy_guard_contract.wasm'));
const policyPath = resolve(process.env.T3N_POLICY_FILE?.trim() || resolve(gatewayRoot, 'policy/privacy-guard-policy.json'));
const manifestPath = resolve(process.env.EVIDENCE_DEPLOYMENT_MANIFEST?.trim() || resolve(evidenceDir, 'deployment-manifest.json'));
const testnetPath = resolve(process.env.EVIDENCE_OUTPUT?.trim() || resolve(evidenceDir, 'testnet-run.json'));
const provisioningStatePath = resolve(process.env.T3N_RUNTIME_PROVISIONING_STATE_PATH?.trim() || '/data/t3n-runtime-provisioning.json');

interface DelegationEvidence {
  readonly memberState: DelegationStatus['memberState'];
  readonly effectiveState: DelegationStatus['effectiveState'];
  readonly checkedFunctions: string[];
  readonly checkedScopes: string[];
}

interface ProvisioningState {
  readonly tenantDid?: unknown;
  readonly contractId?: unknown;
  readonly contractVersion?: unknown;
  readonly numericContractId?: unknown;
}

function configuredEgressHosts(): string[] {
  const candidates = [process.env.SECURITY_API_URL, process.env.SECURITY_VERIFICATION_URL];
  if (process.env.EVIDENCE_RUN_DESTINATION_BINDING === 'true') candidates.push(process.env.EVIDENCE_DESTINATION_B_URL);
  const configured = candidates
    .map((value) => value?.trim())
    .filter((value): value is string => Boolean(value));
  if (configured.length === 0) return ['postman-echo.com'];
  return [...new Set(configured.map((value) => {
    const parsed = new URL(value);
    if (parsed.protocol !== 'https:') throw new Error('Evidence egress endpoints must use HTTPS');
    return parsed.hostname.toLowerCase();
  }))];
}

function assertEffectiveDelegation(label: string, status: DelegationStatus): void {
  if (status.memberState !== 'ACTIVE' || status.effectiveState !== 'ACTIVE') {
    throw new Error(`${label} delegation is not effectively authorised by T3N`);
  }
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

async function resolveNumericContractId(tenantDid: string, contractId: string, contractVersion: string): Promise<number | null> {
  const configured = Number(process.env.T3N_CONTRACT_NUMERIC_ID);
  if (Number.isInteger(configured) && configured > 0) return configured;
  try {
    const state = JSON.parse(await readFile(provisioningStatePath, 'utf8')) as ProvisioningState;
    if (
      state.tenantDid === tenantDid
      && state.contractId === contractId
      && state.contractVersion === contractVersion
      && typeof state.numericContractId === 'number'
      && Number.isInteger(state.numericContractId)
      && state.numericContractId > 0
    ) return state.numericContractId;
  } catch {
    return null;
  }
  return null;
}

function runNpmScript(name: string, extraEnv: NodeJS.ProcessEnv = {}): void {
  const result = spawnSync('npm', ['run', name], {
    cwd: gatewayRoot,
    env: { ...process.env, ...extraEnv },
    stdio: 'inherit',
  });
  if (result.status !== 0) throw new Error(`${name} failed`);
}

const config = readGatewayConfig();
if (config.network !== 'testnet' && process.env.EVIDENCE_ALLOW_PRODUCTION !== 'true') {
  throw new Error('Live evidence orchestration is restricted to testnet unless EVIDENCE_ALLOW_PRODUCTION=true');
}
if (!config.agentApiKey) throw new Error('T3N_AGENT_API_KEY is required for live evidence');
if (!config.executorApiKey) throw new Error('T3N_EXECUTOR_API_KEY is required for live evidence');
if (process.env.EVIDENCE_RUN_DESTINATION_BINDING === 'true' && config.network !== 'testnet') {
  throw new Error('Destination-binding mutation evidence is restricted to T3N testnet and cannot run in production');
}

const sourceRevision = resolveSourceRevision(repositoryRoot);
if (!sourceRevision.sourceTreeClean && process.env.EVIDENCE_ALLOW_DIRTY_SOURCE !== 'true') {
  throw new Error('Live evidence requires a clean source tree. Set EVIDENCE_ALLOW_DIRTY_SOURCE=true only to record an explicitly DIRTY non-submission run.');
}

const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const tenantSession = new T3nSession(config, trustFloorStore);
const agentSession = new AgentSession(config, trustFloorStore);
const executorSession = new ExecutorSession(config, trustFloorStore);
const agentCardRegistry = new AgentCardRegistry(agentSession, undefined, undefined, config.a2aPublicUrl);
const proposalDelegation = new DelegationService(tenantSession, agentSession, PROPOSAL_DELEGATION_REQUIREMENTS);
const executorDelegation = new DelegationService(tenantSession, executorSession, EXECUTOR_DELEGATION_REQUIREMENTS);
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

let identity: { contractId: string; contractVersion: string };
try {
  identity = await contract.identity();
} catch {
  throw new Error('T3N contract is not resolved; complete runtime provisioning before generating live evidence');
}
const contractId = identity.contractId;
const contractVersion = identity.contractVersion;
if (contractVersion !== config.contractVersion) {
  throw new Error(`Resolved contract version ${contractVersion} does not match configured ${config.contractVersion}`);
}
const numericContractId = await resolveNumericContractId(tenantDid, contractId, contractVersion);
if (!numericContractId) {
  throw new Error('Live evidence requires the numeric contract id from T3N runtime provisioning or T3N_CONTRACT_NUMERIC_ID');
}

runNpmScript('contract:setup-policy', {
  T3N_CONTRACT_NUMERIC_ID: String(numericContractId),
  T3N_POLICY_FILE: policyPath,
});

const manifest: DeploymentManifest = {
  source: 'T3N_TESTNET', generatedAt: new Date().toISOString(), sourceCommitSha: sourceRevision.sourceCommitSha,
  sourceTreeClean: sourceRevision.sourceTreeClean, network: config.network, sdkVersion: '5.2.0', tenantDid, agentDid, executorDid,
  agentRegistrationState: agentRegistration.state, agentCardUri: agentRegistration.cardUri, agentCardSha256: agentRegistration.cardSha256,
  agentCardVerifiedAt: agentRegistration.verifiedAt, agentCardServices: agentRegistration.services, contractId, numericContractId,
  contractVersion, wasmSha256, policyVersion: policy.document.version, policyHash: policy.hash, trustAnchorVerified: true,
  trustManifestFloorPersisted: true, trustManifestVersion: persistedTrustFloor.version,
};
assertManifestIdentity(manifest);
if (manifest.contractVersion !== config.contractVersion) throw new Error('Deployment manifest contract version differs from configured version');

const sensitiveValues = [config.apiKey, config.agentApiKey, config.executorApiKey, process.env.SECURITY_API_KEY, process.env.EVIDENCE_SENTINEL_SECRET, process.env.AI_API_KEY, config.gatewayServiceToken, config.remediationCapabilityKey];
const serializedManifest = `${JSON.stringify(manifest, null, 2)}\n`;
assertNoSecretLeak(serializedManifest, sensitiveValues);
await mkdir(dirname(manifestPath), { recursive: true });
await writeFile(manifestPath, serializedManifest, { encoding: 'utf8', mode: 0o600 });

if (process.env.EVIDENCE_PREPARE_EGRESS === 'true') {
  if (!process.env.SECURITY_API_URL?.startsWith('https://')) throw new Error('SECURITY_API_URL is required when preparing verifiable remediation evidence');
  if (!process.env.SECURITY_VERIFICATION_URL?.startsWith('https://')) throw new Error('SECURITY_VERIFICATION_URL is required when preparing verifiable remediation evidence');
  runNpmScript('contract:setup-remediation', { T3N_CONTRACT_NUMERIC_ID: String(numericContractId) });
}

await proposalDelegation.grant({ contractId, versionReq: contractVersion, functions: [...PROPOSAL_DELEGATION_REQUIREMENTS.functions], scopes: [...PROPOSAL_DELEGATION_REQUIREMENTS.scopes], allowedHosts: [] });
await executorDelegation.grant({ contractId, versionReq: contractVersion, functions: [...EXECUTOR_DELEGATION_REQUIREMENTS.functions], scopes: [...EXECUTOR_DELEGATION_REQUIREMENTS.scopes], allowedHosts: configuredEgressHosts() });

const proposalEffectiveStatus = await proposalDelegation.status(contractId);
const executorEffectiveStatus = await executorDelegation.status(contractId);
assertEffectiveDelegation('Proposal Agent', proposalEffectiveStatus);
assertEffectiveDelegation('Protected Executor', executorEffectiveStatus);

runNpmScript('evidence:testnet', {
  EVIDENCE_OUTPUT: testnetPath,
  T3N_CONTRACT_WASM_PATH: wasmPath,
  T3N_CONTRACT_NUMERIC_ID: String(numericContractId),
});

const evidence = JSON.parse(await readFile(testnetPath, 'utf8')) as TestnetEvidenceIdentity & {
  scenarios?: Array<{ status?: string }>;
  delegation?: { proposal?: DelegationEvidence; executor?: DelegationEvidence };
};
evidence.sourceCommitSha = sourceRevision.sourceCommitSha;
evidence.sourceTreeClean = sourceRevision.sourceTreeClean;
const serializedEvidence = `${JSON.stringify(evidence, null, 2)}\n`;
assertNoSecretLeak(serializedEvidence, sensitiveValues);
await writeFile(testnetPath, serializedEvidence, { encoding: 'utf8', mode: 0o600 });
assertEvidenceMatchesDeployment(manifest, evidence);
if (evidence.scenarios?.some((scenario) => scenario.status === 'FAIL')) throw new Error('T3N testnet evidence contains FAIL scenarios');
if (!evidence.delegation?.proposal || !evidence.delegation.executor) throw new Error('T3N testnet evidence is missing effective delegation verdicts');
for (const [label, observed, runtime] of [
  ['Proposal Agent', evidence.delegation.proposal, proposalEffectiveStatus],
  ['Protected Executor', evidence.delegation.executor, executorEffectiveStatus],
] as const) {
  if (observed.memberState !== runtime.memberState || observed.effectiveState !== runtime.effectiveState) throw new Error(`${label} evidence delegation state differs from the live check`);
  if (!sameStrings(observed.checkedFunctions, runtime.checkedFunctions) || !sameStrings(observed.checkedScopes, runtime.checkedScopes)) throw new Error(`${label} evidence delegation restrictions differ from the live check`);
}

console.info(JSON.stringify({ manifestPath, testnetPath, sourceCommitSha: sourceRevision.sourceCommitSha, sourceTreeClean: sourceRevision.sourceTreeClean, contractId, contractVersion, wasmSha256, policyVersion: policy.document.version, policyHash: policy.hash, proposalAgentDid: agentDid, protectedExecutorDid: executorDid, proposalEffectiveAccess: proposalEffectiveStatus.effectiveState, executorEffectiveAccess: executorEffectiveStatus.effectiveState, agentRegistrationState: agentRegistration.state, agentCardSha256: agentRegistration.cardSha256, trustManifestVersion: persistedTrustFloor.version, trustFloorPersisted: true, evidenceLinked: true }, null, 2));
