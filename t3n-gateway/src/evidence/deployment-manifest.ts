import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { AgentRegistrationState } from '../agent/agent-card.js';

export interface DeploymentManifest {
  source: 'T3N_TESTNET';
  generatedAt: string;
  sourceCommitSha: string;
  sourceTreeClean: boolean;
  network: string;
  sdkVersion: '5.2.0';
  tenantDid: string;
  agentDid: string;
  executorDid: string;
  agentRegistrationState: AgentRegistrationState;
  agentCardUri: string | null;
  agentCardSha256: string | null;
  agentCardVerifiedAt: string;
  agentCardServices: readonly string[];
  contractId: string;
  numericContractId: number | null;
  contractVersion: string;
  wasmSha256: string;
  policyVersion: string;
  policyHash: string;
  trustAnchorVerified: true;
  trustManifestFloorPersisted: true;
  trustManifestVersion: number;
}

export interface TestnetEvidenceIdentity {
  source?: string;
  sourceCommitSha: string;
  sourceTreeClean: boolean;
  network: string;
  sdkVersion: string;
  tenantDid: string;
  agentDid: string;
  executorDid: string;
  contractId: string;
  contractVersion: string;
  wasmSha256: string | null;
  policyVersion: string | null;
  policyHash: string | null;
}

export async function sha256File(path: string): Promise<string> {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

function assertRegisteredAgentCardServices(services: readonly string[]): void {
  const allowed = new Set(['DID', 'A2A']);
  const unique = new Set(services);
  if (!services.includes('DID')) throw new Error('Registered Agent evidence requires the DID service');
  if (unique.size !== services.length) throw new Error('Registered Agent evidence contains duplicate services');
  if (services.some((service) => !allowed.has(service))) throw new Error('Registered Agent evidence contains an unsupported service');
  if (services.length > allowed.size) throw new Error('Registered Agent evidence contains too many services');
}

export function assertManifestIdentity(manifest: DeploymentManifest): void {
  if (!/^[a-f0-9]{40}$/.test(manifest.sourceCommitSha)) {
    throw new Error('Deployment manifest contains an invalid source commit SHA');
  }
  if (typeof manifest.sourceTreeClean !== 'boolean') {
    throw new Error('Deployment manifest requires an explicit source tree state');
  }
  if (!manifest.tenantDid.startsWith('did:t3n:') || !manifest.agentDid.startsWith('did:t3n:') || !manifest.executorDid.startsWith('did:t3n:')) {
    throw new Error('Deployment manifest requires canonical T3N DIDs');
  }
  if (new Set([manifest.tenantDid, manifest.agentDid, manifest.executorDid]).size !== 3) {
    throw new Error('Tenant DID, proposal Agent DID and protected Executor DID must be different');
  }
  if (!/^[a-f0-9]{64}$/.test(manifest.wasmSha256)) {
    throw new Error('Deployment manifest contains an invalid WASM SHA-256');
  }
  if (!manifest.policyVersion || !/^[a-f0-9]{64}$/.test(manifest.policyHash)) {
    throw new Error('Deployment manifest contains invalid versioned policy provenance');
  }
  if (!['REGISTERED', 'NOT_REGISTERED', 'MISMATCH', 'UNAVAILABLE'].includes(manifest.agentRegistrationState)) {
    throw new Error('Deployment manifest contains an invalid Agent registration state');
  }
  if (!manifest.agentCardVerifiedAt || Number.isNaN(Date.parse(manifest.agentCardVerifiedAt))) {
    throw new Error('Deployment manifest contains an invalid Agent Card verification timestamp');
  }
  if (manifest.agentRegistrationState === 'REGISTERED') {
    if (!manifest.agentCardUri?.startsWith('https://')) throw new Error('Registered Agent evidence requires a public HTTPS card URI');
    if (!manifest.agentCardSha256 || !/^[a-f0-9]{64}$/.test(manifest.agentCardSha256)) throw new Error('Registered Agent evidence requires a valid Agent Card SHA-256');
    assertRegisteredAgentCardServices(manifest.agentCardServices);
  }
  if (manifest.trustAnchorVerified !== true || manifest.trustManifestFloorPersisted !== true) {
    throw new Error('Deployment manifest must prove verified trust anchor and persisted rollback floor');
  }
  if (!Number.isSafeInteger(manifest.trustManifestVersion) || manifest.trustManifestVersion < 1) {
    throw new Error('Deployment manifest contains an invalid trust manifest version');
  }
}

export function assertEvidenceMatchesDeployment(manifest: DeploymentManifest, evidence: TestnetEvidenceIdentity): void {
  const checks: Array<[string, unknown, unknown]> = [
    ['source', 'T3N_TESTNET', evidence.source ?? 'T3N_TESTNET'],
    ['sourceCommitSha', manifest.sourceCommitSha, evidence.sourceCommitSha],
    ['sourceTreeClean', manifest.sourceTreeClean, evidence.sourceTreeClean],
    ['network', manifest.network, evidence.network],
    ['sdkVersion', manifest.sdkVersion, evidence.sdkVersion],
    ['tenantDid', manifest.tenantDid, evidence.tenantDid],
    ['agentDid', manifest.agentDid, evidence.agentDid],
    ['executorDid', manifest.executorDid, evidence.executorDid],
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
