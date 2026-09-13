import assert from 'node:assert/strict';
import test from 'node:test';
import { assertEvidenceMatchesDeployment, assertManifestIdentity, type DeploymentManifest } from './deployment-manifest.js';

function manifest(): DeploymentManifest {
  return {
    source: 'T3N_TESTNET',
    generatedAt: '2026-09-12T00:00:00.000Z',
    network: 'testnet',
    sdkVersion: '5.2.0',
    tenantDid: 'did:t3n:tenant',
    agentDid: 'did:t3n:agent',
    agentRegistrationState: 'REGISTERED',
    agentCardUri: 'https://testnet.t3n.io/api/agent-card/did%3At3n%3Aagent',
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

test('rejects same tenant and agent DID', () => {
  const value = manifest();
  value.agentDid = value.tenantDid;
  assert.throws(() => assertManifestIdentity(value), /must be different/);
});

test('requires a registered Agent Card that exposes only the DID service', () => {
  const value = manifest();
  value.agentRegistrationState = 'MISMATCH';
  assert.throws(() => assertManifestIdentity(value), /public Agent Card/i);
});

test('accepts matching deployment and testnet evidence identities', () => {
  const value = manifest();
  assert.doesNotThrow(() => assertEvidenceMatchesDeployment(value, {
    source: 'T3N_TESTNET',
    network: value.network,
    sdkVersion: value.sdkVersion,
    tenantDid: value.tenantDid,
    agentDid: value.agentDid,
    contractId: value.contractId,
    contractVersion: value.contractVersion,
    wasmSha256: value.wasmSha256,
    policyVersion: value.policyVersion,
    policyHash: value.policyHash,
  }));
});

test('rejects a different WASM contract or policy identity', () => {
  const value = manifest();
  assert.throws(() => assertEvidenceMatchesDeployment(value, {
    source: 'T3N_TESTNET', network: value.network, sdkVersion: value.sdkVersion,
    tenantDid: value.tenantDid, agentDid: value.agentDid, contractId: value.contractId,
    contractVersion: '0.4.1', wasmSha256: 'c'.repeat(64),
    policyVersion: '2026-09-12.2', policyHash: 'd'.repeat(64),
  }), /Evidence mismatch/);
});

test('rejects missing trust provenance in deployment manifest', () => {
  const value = manifest();
  value.trustManifestFloorPersisted = false as true;
  assert.throws(() => assertManifestIdentity(value), /trust anchor and persisted rollback floor/i);
});
