import { constants } from 'node:fs';
import { access } from 'node:fs/promises';
import { resolve } from 'node:path';

interface RuntimeArtifact {
  label: string;
  path: string;
  mode: number;
}

const runtimeDataDirectory = process.env.NODE_ENV === 'production' ? '/data' : resolve('data');
const artifacts: RuntimeArtifact[] = [
  {
    label: 'contract registration script',
    path: resolve('dist/scripts/register-contract.js'),
    mode: constants.R_OK,
  },
  {
    label: 'policy setup script',
    path: resolve('dist/scripts/setup-policy.js'),
    mode: constants.R_OK,
  },
  {
    label: 'remediation setup script',
    path: resolve('dist/scripts/setup-remediation-secrets.js'),
    mode: constants.R_OK,
  },
  {
    label: 'Agent Card verification script',
    path: resolve('dist/scripts/agent-card-verify.js'),
    mode: constants.R_OK,
  },
  {
    label: 'Agent Card publication script',
    path: resolve('dist/scripts/agent-card-publish.js'),
    mode: constants.R_OK,
  },
  {
    label: 'T3N policy document',
    path: resolve(process.env.T3N_POLICY_FILE ?? 'policy/privacy-guard-policy.json'),
    mode: constants.R_OK,
  },
  {
    label: 'T3N contract WASM',
    path: resolve(process.env.T3N_CONTRACT_WASM_PATH ?? 'contracts/privacy_guard_contract.wasm'),
    mode: constants.R_OK,
  },
  {
    label: 'runtime data directory',
    path: runtimeDataDirectory,
    mode: constants.R_OK | constants.W_OK,
  },
];

const failures: string[] = [];
for (const artifact of artifacts) {
  try {
    await access(artifact.path, artifact.mode);
  } catch {
    failures.push(`${artifact.label}: ${artifact.path}`);
  }
}

if (failures.length > 0) {
  throw new Error(`Gateway runtime provisioning artifacts are incomplete:\n${failures.join('\n')}`);
}

console.info(JSON.stringify({
  status: 'READY',
  checkedArtifacts: artifacts.map(({ label, path }) => ({ label, path })),
}, null, 2));
