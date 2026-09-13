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
    agentDid: 'did:t3n:0123456789abcdef0123456789abcdef01234567',
    agentRegistrationState: 'REGISTERED',
    agentCardUri: 'https://node.example/api/agent-card/did:t3n:0123456789abcdef0123456789abcdef01234567',
    agentCardSha256: 'c'.repeat(64),
    agentCardVerifiedAt: '2026-09-12T00:00:01.000Z',
    agentCardServices: ['DID'],
    contractId: 'z:tenant:privacy-guard',
    numericContractId: 123,
    contractVersion: '0.3.0',
    wasmSha256: 'a'.repeat(64),
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
    network: value.network,
    sdkVersion: value.sdkVersion,
    tenantDid: value.tenantDid,
    agentDid: value.agentDid,
    contractId: value.contractId,
    contractVersion: value.contractVersion,
    wasmSha256: value.wasmSha256,
  }));
});

test('rejects a different WASM hash or contract version', () => {
  const value = manifest();
  assert.throws(() => assertEvidenceMatchesDeployment(value, {
    source: 'T3N_TESTNET', network: value.network, sdkVersion: value.sdkVersion,
    tenantDid: value.tenantDid, agentDid: value.agentDid, contractId: value.contractId,
    contractVersion: '0.3.1', wasmSha256: 'b'.repeat(64),
  }), /Evidence mismatch/);
});
