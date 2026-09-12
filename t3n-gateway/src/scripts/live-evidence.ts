import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { AgentSession } from '../agent/agent-session.js';
import { DelegationService } from '../agent/delegation-service.js';
import { readGatewayConfig } from '../config/env.js';
import { PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import { assertEvidenceMatchesDeployment, assertManifestIdentity, sha256File, type DeploymentManifest, type TestnetEvidenceIdentity } from '../evidence/deployment-manifest.js';
import { assertNoSecretLeak } from '../evidence/leak-detector.js';
import { T3nSession } from '../t3n/session.js';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const gatewayRoot = resolve(scriptDir, '../..');
const repositoryRoot = resolve(gatewayRoot, '..');
const evidenceDir = resolve(repositoryRoot, 'docs/evidence');
const wasmPath = resolve(process.env.T3N_CONTRACT_WASM_PATH ?? resolve(repositoryRoot, 'contracts/privacy-guard/target/wasm32-wasip2/release/privacy_guard_contract.wasm'));
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

const tenantSession = new T3nSession(config);
const agentSession = new AgentSession(config);
const delegation = new DelegationService(tenantSession, agentSession);
const contract = new PrivacyGuardContractService(config, tenantSession, agentSession);
await tenantSession.connect();
await agentSession.connect();

const tenantDid = tenantSession.getTenantDid();
const agentDid = agentSession.getAgentDid();
if (tenantDid === agentDid) throw new Error('Tenant DID and agent DID must be different');
const wasmSha256 = await sha256File(wasmPath);

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
} catch (error) {
  const tenant = new TenantClient({ t3n: tenantSession.getClient(), baseUrl: getNodeUrl(), tenantDid });
  const result = await tenant.contracts.register({ tail: config.contractTail, version: config.contractVersion, wasm: await readFile(wasmPath) });
  numericContractId = result.contract_id;
  const identity = await contract.identity();
  contractId = identity.contractId;
  contractVersion = identity.contractVersion;
}

const manifest: DeploymentManifest = {
  source: 'T3N_TESTNET',
  generatedAt: new Date().toISOString(),
  network: config.network,
  sdkVersion: '5.2.0',
  tenantDid,
  agentDid,
  contractId,
  numericContractId,
  contractVersion,
  wasmSha256,
};
assertManifestIdentity(manifest);
if (manifest.contractVersion !== config.contractVersion) throw new Error('Deployment manifest contract version differs from configured version');

const sensitiveValues = [
  config.apiKey,
  config.agentApiKey,
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
  if (!numericContractId) throw new Error('T3N_CONTRACT_NUMERIC_ID is required to prepare the private remediation map for an existing contract');
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

await delegation.grant({
  contractId,
  versionReq: contractVersion,
  functions: ['evaluate-action', 'execute-remediation', 'verify-remediation'],
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
console.info(JSON.stringify({ manifestPath, testnetPath, contractId, contractVersion, wasmSha256, evidenceLinked: true }, null, 2));
