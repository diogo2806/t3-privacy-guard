import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

export interface DeploymentManifest {
  source: 'T3N_TESTNET';
  generatedAt: string;
  network: string;
  sdkVersion: '5.2.0';
  tenantDid: string;
  agentDid: string;
  contractId: string;
  numericContractId: number | null;
  contractVersion: string;
  wasmSha256: string;
  policyVersion: string;
  policyHash: string;
}

export interface TestnetEvidenceIdentity {
  source?: string;
  network: string;
  sdkVersion: string;
  tenantDid: string;
  agentDid: string;
  contractId: string;
  contractVersion: string;
  wasmSha256: string | null;
  policyVersion: string | null;
  policyHash: string | null;
}

export async function sha256File(path: string): Promise<string> {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

export function assertManifestIdentity(manifest: DeploymentManifest): void {
  if (!manifest.tenantDid.startsWith('did:t3n:') || !manifest.agentDid.startsWith('did:t3n:')) {
    throw new Error('Deployment manifest requires canonical T3N DIDs');
  }
  if (manifest.tenantDid === manifest.agentDid) {
    throw new Error('Tenant DID and agent DID must be different');
  }
  if (!/^[a-f0-9]{64}$/.test(manifest.wasmSha256)) {
    throw new Error('Deployment manifest contains an invalid WASM SHA-256');
  }
  if (!manifest.policyVersion || !/^[a-f0-9]{64}$/.test(manifest.policyHash)) {
    throw new Error('Deployment manifest contains invalid versioned policy provenance');
  }
}

export function assertEvidenceMatchesDeployment(manifest: DeploymentManifest, evidence: TestnetEvidenceIdentity): void {
  const checks: Array<[string, unknown, unknown]> = [
    ['source', 'T3N_TESTNET', evidence.source ?? 'T3N_TESTNET'],
    ['network', manifest.network, evidence.network],
    ['sdkVersion', manifest.sdkVersion, evidence.sdkVersion],
    ['tenantDid', manifest.tenantDid, evidence.tenantDid],
    ['agentDid', manifest.agentDid, evidence.agentDid],
    ['contractId', manifest.contractId, evidence.contractId],
    ['contractVersion', manifest.contractVersion, evidence.contractVersion],
    ['wasmSha256', manifest.wasmSha256, evidence.wasmSha256],
    ['policyVersion', manifest.policyVersion, evidence.policyVersion],
    ['policyHash', manifest.policyHash, evidence.policyHash],
  ];
  for (const [field, expected, actual] of checks) {
    if (expected !== actual) throw new Error(`Evidence mismatch for ${field}`);
  }
}
