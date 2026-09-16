import assert from 'node:assert/strict';
import test from 'node:test';
import {
  configuredEnterpriseHosts,
  provisioningStateMatches,
  runtimeProvisioningEnabled,
  type RuntimeProvisioningState,
} from './runtime-provisioning.js';

test('runtime provisioning defaults to production testnet containers only', () => {
  assert.equal(runtimeProvisioningEnabled({ network: 'testnet' }, { NODE_ENV: 'production' }), true);
  assert.equal(runtimeProvisioningEnabled({ network: 'testnet' }, { NODE_ENV: 'development' }), false);
  assert.equal(runtimeProvisioningEnabled({ network: 'production' }, { NODE_ENV: 'production' }), false);
});

test('runtime provisioning explicit override is honored', () => {
  assert.equal(runtimeProvisioningEnabled({ network: 'testnet' }, { T3N_RUNTIME_PROVISIONING: 'false', NODE_ENV: 'production' }), false);
  assert.equal(runtimeProvisioningEnabled({ network: 'production' }, { T3N_RUNTIME_PROVISIONING: 'true', NODE_ENV: 'production' }), true);
  assert.throws(
    () => runtimeProvisioningEnabled({ network: 'testnet' }, { T3N_RUNTIME_PROVISIONING: 'yes', NODE_ENV: 'production' }),
    /must be true or false/,
  );
});

test('enterprise hosts use only real HTTPS endpoints and are deduplicated', () => {
  assert.deepEqual(configuredEnterpriseHosts({
    SECURITY_API_URL: 'https://security.example.com/private/remediate?tenant=demo',
    SECURITY_VERIFICATION_URL: 'https://verify.example.com/private/read-back#state',
  }), ['security.example.com', 'verify.example.com']);

  assert.deepEqual(configuredEnterpriseHosts({
    SECURITY_API_URL: 'https://example.invalid/remediation',
    SECURITY_VERIFICATION_URL: 'https://postman-echo.com/get',
  }), []);

  assert.deepEqual(configuredEnterpriseHosts({
    SECURITY_API_URL: 'http://security.example.com/remediate',
    SECURITY_VERIFICATION_URL: 'https://security.example.com/read-back',
  }), ['security.example.com']);
});

test('persisted numeric id is reusable only for the same tenant contract and version', () => {
  const state: RuntimeProvisioningState = {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.0',
    numericContractId: 42,
    updatedAt: '2026-09-16T15:00:00.000Z',
  };

  assert.equal(provisioningStateMatches(state, {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.0',
  }), true);
  assert.equal(provisioningStateMatches(state, {
    tenantDid: 'did:t3n:other',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.0',
  }), false);
  assert.equal(provisioningStateMatches(state, {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.5.0',
  }), false);
});
