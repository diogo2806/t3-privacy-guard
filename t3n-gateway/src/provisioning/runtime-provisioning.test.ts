import assert from 'node:assert/strict';
import test from 'node:test';
import type { AgentCardPublicationRequest } from '../agent/agent-card-publisher.js';
import {
  buildAdminProvisioningPlan,
  configuredEnterpriseHosts,
  contractVersionAction,
  executorDelegationGrantRequest,
  parseProvisioningState,
  persistRemoteProvisioningState,
  provisioningStateMatches,
  readRemoteProvisioningState,
  reconcileAgentCard,
  reconcileAgentCardIndependently,
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

test('Agent Card mismatch remains visible without becoming a fatal provisioning error', async () => {
  const state = await reconcileAgentCardIndependently(
    async () => { throw new Error('Published Agent Card did not verify as REGISTERED (MISMATCH)'); },
    async () => 'MISMATCH',
  );
  assert.equal(state, 'MISMATCH');
});

test('Agent Card observation failure remains non-fatal and explicit', async () => {
  const state = await reconcileAgentCardIndependently(
    async () => { throw new Error('publish failed'); },
    async () => { throw new Error('verify failed'); },
  );
  assert.equal(state, 'UNAVAILABLE');
});

test('Agent Card registered state is preserved when reconciliation succeeds', async () => {
  const state = await reconcileAgentCardIndependently(
    async () => 'REGISTERED',
    async () => 'MISMATCH',
  );
  assert.equal(state, 'REGISTERED');
});

test('runtime Agent Card reconciliation forwards the authenticated Tenant/Admin DID to the shared publisher', async () => {
  const adminDid = 'did:t3n:tenant-admin-real';
  const agentDid = 'did:t3n:proposal-agent-real';
  const adminClient = { kind: 'tenant-admin-client' };
  const config = {
    orgDid: 'did:t3n:organization123',
    agentApiKey: 't3n_key_proposal.test-secret',
    apiKey: `0x${'a'.repeat(64)}`,
    a2aPublicUrl: 'https://gateway.example.com/a2a',
  } as unknown as Parameters<typeof reconcileAgentCard>[0];
  const tenantSession = {
    getTenantDid: () => adminDid,
    getClient: () => adminClient,
  } as unknown as Parameters<typeof reconcileAgentCard>[1];
  const agentSession = {
    getAgentDid: () => agentDid,
  } as unknown as Parameters<typeof reconcileAgentCard>[2];
  let verifyCalls = 0;
  const registry = {
    verify: async () => ({ state: verifyCalls++ === 0 ? 'MISMATCH' : 'REGISTERED' }),
  } as unknown as Parameters<typeof reconcileAgentCard>[3];
  let capturedRequest: AgentCardPublicationRequest | undefined;

  const state = await reconcileAgentCard(
    config,
    tenantSession,
    agentSession,
    registry,
    async () => undefined,
    async (request) => { capturedRequest = request; },
  );

  assert.equal(state, 'REGISTERED');
  assert.ok(capturedRequest);
  assert.equal(capturedRequest.adminDid, adminDid);
  assert.equal(capturedRequest.ownerDid, config.orgDid);
  assert.equal(capturedRequest.agentDid, agentDid);
  assert.equal(capturedRequest.adminClient, adminClient);
});

test('contract version migration registers absent or older versions and reuses the packaged version', () => {
  assert.equal(contractVersionAction(null, '0.4.2'), 'REGISTER');
  assert.equal(contractVersionAction('0.4.0', '0.4.2'), 'REGISTER');
  assert.equal(contractVersionAction('0.4.1', '0.4.2'), 'REGISTER');
  assert.equal(contractVersionAction('0.4.2', '0.4.2'), 'REUSE');
});

test('contract version migration fails closed when T3N is newer than the packaged artifact', () => {
  assert.throws(
    () => contractVersionAction('0.4.3', '0.4.2'),
    /newer than packaged/,
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

test('executor grant keeps T3N least privilege even when enterprise integration is absent', () => {
  assert.deepEqual(executorDelegationGrantRequest('z:tenant:privacy-guard', '0.4.2', {}), {
    contractId: 'z:tenant:privacy-guard',
    versionReq: '0.4.2',
    functions: ['execute-remediation', 'verify-remediation'],
    scopes: ['incident_id', 'credential_id', 'reason', 'verified_contacts.email.value'],
    allowedHosts: [],
  });
});

test('executor grant adds only canonical real HTTPS enterprise hosts when configured', () => {
  assert.deepEqual(executorDelegationGrantRequest('z:tenant:privacy-guard', '0.4.2', {
    SECURITY_API_URL: 'https://security.example.com/private/remediate',
    SECURITY_VERIFICATION_URL: 'https://verify.example.com/private/read-back',
  }).allowedHosts, ['security.example.com', 'verify.example.com']);
});

test('admin provisioning reconciles existing maps even when no numeric contract id is locally available', () => {
  const plan = buildAdminProvisioningPlan(null, {
    T3N_CONTRACT_NUMERIC_ID: '999',
    SECURITY_API_KEY: 'a'.repeat(64),
    SECURITY_API_URL: 'https://security.example.com/private/remediate',
    SECURITY_VERIFICATION_URL: 'https://security.example.com/private/read-back',
  });

  assert.deepEqual(plan.map(({ scriptName }) => scriptName), [
    'setup-policy.js',
    'setup-remediation-secrets.js',
  ]);
  for (const step of plan) assert.equal(step.env.T3N_CONTRACT_NUMERIC_ID, undefined);
});

test('admin provisioning forwards a known numeric contract id to map creation capable scripts', () => {
  const plan = buildAdminProvisioningPlan(42, {
    SECURITY_API_KEY: 'a'.repeat(64),
    SECURITY_API_URL: 'https://security.example.com/private/remediate',
    SECURITY_VERIFICATION_URL: 'https://verify.example.com/private/read-back',
  });

  assert.deepEqual(plan.map(({ scriptName }) => scriptName), [
    'setup-policy.js',
    'setup-remediation-secrets.js',
  ]);
  for (const step of plan) assert.equal(step.env.T3N_CONTRACT_NUMERIC_ID, '42');
});

test('admin provisioning keeps policy reconciliation independent from incomplete remediation configuration', () => {
  const plan = buildAdminProvisioningPlan(null, {
    SECURITY_API_KEY: 'a'.repeat(64),
  });

  assert.deepEqual(plan.map(({ scriptName }) => scriptName), ['setup-policy.js']);
});

test('persisted numeric id is reusable only for the same tenant contract and version', () => {
  const state: RuntimeProvisioningState = {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.2',
    numericContractId: 42,
    updatedAt: '2026-09-17T13:00:00.000Z',
  };

  assert.equal(provisioningStateMatches(state, {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.2',
  }), true);
  assert.equal(provisioningStateMatches(state, {
    tenantDid: 'did:t3n:other',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.2',
  }), false);
  assert.equal(provisioningStateMatches(state, {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.5.0',
  }), false);
});

test('provisioning state parser rejects malformed or non-positive numeric ids', () => {
  assert.equal(parseProvisioningState('{"tenantDid":"did:t3n:a"}'), null);
  assert.equal(parseProvisioningState(JSON.stringify({
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.2',
    numericContractId: 0,
    updatedAt: '2026-09-17T13:00:00.000Z',
  })), null);
});

test('remote T3N provisioning state persists with contract-only ACL and strict read-back', async () => {
  const state: RuntimeProvisioningState = {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.2',
    numericContractId: 42,
    updatedAt: '2026-09-17T13:00:00.000Z',
  };
  let stored: string | null = null;
  let created: unknown;
  const control = {
    canonicalName: (tail: string) => `z:tenant123:${tail}`,
    maps: {
      create: async (input: unknown) => { created = input; },
      update: async () => undefined,
    },
    executeControl: async (name: string, input: Record<string, string>) => {
      if (name === 'map-entry-set') {
        stored = input.value;
        return {};
      }
      if (name === 'map-entry-get') return stored;
      throw new Error('unexpected control operation');
    },
  } as unknown as Parameters<typeof persistRemoteProvisioningState>[0];

  await persistRemoteProvisioningState(control, state);
  assert.deepEqual(created, {
    tail: 'privacy-guard-runtime',
    visibility: 'private',
    writers: { only: [42] },
    readers: { only: [42] },
  });
  assert.deepEqual(await readRemoteProvisioningState(control), state);
});

test('remote T3N provisioning state repairs ACL when its map already exists', async () => {
  const state: RuntimeProvisioningState = {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.2',
    numericContractId: 77,
    updatedAt: '2026-09-17T13:01:00.000Z',
  };
  let stored: string | null = null;
  let updated: unknown;
  const control = {
    canonicalName: (tail: string) => `z:tenant123:${tail}`,
    maps: {
      create: async () => { throw new Error('map already exists'); },
      update: async (tail: string, patch: unknown) => { updated = { tail, patch }; },
    },
    executeControl: async (name: string, input: Record<string, string>) => {
      if (name === 'map-entry-set') {
        stored = input.value;
        return {};
      }
      if (name === 'map-entry-get') return stored;
      throw new Error('unexpected control operation');
    },
  } as unknown as Parameters<typeof persistRemoteProvisioningState>[0];

  await persistRemoteProvisioningState(control, state);
  assert.deepEqual(updated, {
    tail: 'privacy-guard-runtime',
    patch: {
      writers: { only: [77] },
      readers: { only: [77] },
    },
  });
});

test('remote T3N provisioning state treats a missing map as no state but not arbitrary control-plane failures', async () => {
  const missing = {
    canonicalName: (tail: string) => `z:tenant123:${tail}`,
    maps: { create: async () => undefined, update: async () => undefined },
    executeControl: async () => { throw Object.assign(new Error('RPC Error: map not found'), { detail: 'map not found' }); },
  } as unknown as Parameters<typeof readRemoteProvisioningState>[0];
  assert.equal(await readRemoteProvisioningState(missing), null);

  const unavailable = {
    canonicalName: (tail: string) => `z:tenant123:${tail}`,
    maps: { create: async () => undefined, update: async () => undefined },
    executeControl: async () => { throw new Error('transport unavailable'); },
  } as unknown as Parameters<typeof readRemoteProvisioningState>[0];
  await assert.rejects(() => readRemoteProvisioningState(unavailable), /could not be read/);
});
