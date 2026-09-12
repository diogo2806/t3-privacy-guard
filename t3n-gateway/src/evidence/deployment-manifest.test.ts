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
    contractId: 'z:tenant:privacy-guard',
    numericContractId: 123,
    contractVersion: '0.3.0',
    wasmSha256: 'a'.repeat(64),
  };
}

test('rejects same tenant and agent DID', () => {
  const value = manifest();
  value.agentDid = value.tenantDid;
  assert.throws(() => assertManifestIdentity(value), /must be different/);
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
