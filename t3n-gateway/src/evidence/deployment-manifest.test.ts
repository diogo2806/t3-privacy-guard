import assert from 'node:assert/strict';
import test from 'node:test';
import { assertEvidenceMatchesDeployment, assertManifestIdentity, type DeploymentManifest } from './deployment-manifest.js';

function manifest(): DeploymentManifest {
  return {
    source: 'T3N_TESTNET',
    generatedAt: '2026-09-12T00:00:00.000Z',
    sourceCommitSha: '1'.repeat(40),
    sourceTreeClean: true,
    network: 'testnet',
    sdkVersion: '5.2.0',
    tenantDid: 'did:t3n:tenant',
    agentDid: 'did:t3n:0123456789abcdef0123456789abcdef01234567',
    executorDid: 'did:t3n:protected-executor-0123456789abcdef',
    agentRegistrationState: 'REGISTERED',
    agentCardUri: 'https://node.example/api/agent-card/did:t3n:0123456789abcdef0123456789abcdef01234567',
    agentCardSha256: 'c'.repeat(64),
    agentCardVerifiedAt: '2026-09-12T00:00:01.000Z',
    agentCardServices: ['DID'],
    contractId: 'z:tenant:privacy-guard',
    numericContractId: 123,
    contractVersion: '0.4.0',
    wasmSha256: 'a'.repeat(64),
    policyVersion: '2026-09-12.1',
    policyHash: 'b'.repeat(64),
    trustAnchorVerified: true,
    trustManifestFloorPersisted: true,
    trustManifestVersion: 42,
  };
}

test('rejects malformed or missing source revision provenance', () => {
  const invalidSha = manifest();
  invalidSha.sourceCommitSha = 'abc1234';
  assert.throws(() => assertManifestIdentity(invalidSha), /source commit SHA/i);

  const missingTreeState = manifest() as DeploymentManifest & { sourceTreeClean: unknown };
  missingTreeState.sourceTreeClean = undefined;
  assert.throws(() => assertManifestIdentity(missingTreeState as DeploymentManifest), /source tree state/i);
});

test('rejects reused tenant proposal-agent or executor DID', () => {
  const tenantAgent = manifest();
  tenantAgent.agentDid = tenantAgent.tenantDid;
  assert.throws(() => assertManifestIdentity(tenantAgent), /must be different/);

  const agentExecutor = manifest();
  agentExecutor.executorDid = agentExecutor.agentDid;
  assert.throws(() => assertManifestIdentity(agentExecutor), /must be different/);
});

test('rejects a REGISTERED claim without matching public card evidence', () => {
  const value = manifest();
  value.agentCardSha256 = null;
  assert.throws(() => assertManifestIdentity(value), /Agent Card SHA-256/);
});

test('negative registration states are preserved without being upgraded to success', () => {
  const value = manifest();
  value.agentRegistrationState = 'NOT_REGISTERED';
  value.agentCardUri = null;
  value.agentCardSha256 = null;
  value.agentCardServices = [];
  assert.doesNotThrow(() => assertManifestIdentity(value));
});

test('accepts matching deployment and testnet evidence identities', () => {
  const value = manifest();
  assert.doesNotThrow(() => assertEvidenceMatchesDeployment(value, {
    source: 'T3N_TESTNET',
    sourceCommitSha: value.sourceCommitSha,
    sourceTreeClean: value.sourceTreeClean,
    network: value.network,
    sdkVersion: value.sdkVersion,
    tenantDid: value.tenantDid,
    agentDid: value.agentDid,
    executorDid: value.executorDid,
    contractId: value.contractId,
    contractVersion: value.contractVersion,
    wasmSha256: value.wasmSha256,
    policyVersion: value.policyVersion,
    policyHash: value.policyHash,
  }));
});

test('rejects source revision mismatch between deployment and testnet evidence', () => {
  const value = manifest();
  assert.throws(() => assertEvidenceMatchesDeployment(value, {
    source: 'T3N_TESTNET', sourceCommitSha: '2'.repeat(40), sourceTreeClean: false,
    network: value.network, sdkVersion: value.sdkVersion, tenantDid: value.tenantDid, agentDid: value.agentDid,
    executorDid: value.executorDid, contractId: value.contractId, contractVersion: value.contractVersion,
    wasmSha256: value.wasmSha256, policyVersion: value.policyVersion, policyHash: value.policyHash,
  }), /Evidence mismatch for sourceCommitSha/);
});

test('rejects a different executor WASM contract or policy identity', () => {
  const value = manifest();
  assert.throws(() => assertEvidenceMatchesDeployment(value, {
    source: 'T3N_TESTNET', sourceCommitSha: value.sourceCommitSha, sourceTreeClean: value.sourceTreeClean,
    network: value.network, sdkVersion: value.sdkVersion,
    tenantDid: value.tenantDid, agentDid: value.agentDid, executorDid: 'did:t3n:other-executor', contractId: value.contractId,
    contractVersion: '0.4.1', wasmSha256: 'd'.repeat(64),
    policyVersion: '2026-09-12.2', policyHash: 'e'.repeat(64),
  }), /Evidence mismatch/);
});

test('rejects missing trust provenance in deployment manifest', () => {
  const value = manifest();
  value.trustManifestFloorPersisted = false as true;
  assert.throws(() => assertManifestIdentity(value), /trust anchor and persisted rollback floor/i);
});
