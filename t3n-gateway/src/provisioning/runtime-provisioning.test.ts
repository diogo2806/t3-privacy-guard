import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import type { AgentCardPublicationRequest } from '../agent/agent-card-publisher.js';
import {
  buildAdminProvisioningPlan,
  configuredEnterpriseHosts,
  contractVersionAction,
  executorDelegationGrantRequest,
  parseProvisioningState,
  provisioningStateMatches,
  reconcileAgentCard,
  reconcileAgentCardIndependently,
  resolveOrRegisterContract,
  reusableNumericContractId,
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

test('contract version migration registers absent or older versions and reuses packaged 0.4.3', () => {
  assert.equal(contractVersionAction(null, '0.4.3'), 'REGISTER');
  assert.equal(contractVersionAction('0.4.0', '0.4.3'), 'REGISTER');
  assert.equal(contractVersionAction('0.4.1', '0.4.3'), 'REGISTER');
  assert.equal(contractVersionAction('0.4.2', '0.4.3'), 'REGISTER');
  assert.equal(contractVersionAction('0.4.3', '0.4.3'), 'REUSE');
});

test('contract version migration fails closed when T3N is newer than the packaged artifact', () => {
  assert.throws(
    () => contractVersionAction('0.4.4', '0.4.3'),
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
  assert.deepEqual(executorDelegationGrantRequest('z:tenant:privacy-guard', '0.4.3', {}), {
    contractId: 'z:tenant:privacy-guard',
    versionReq: '0.4.3',
    functions: ['execute-remediation', 'verify-remediation'],
    scopes: ['incident_id', 'credential_id', 'reason', 'verified_contacts.email.value'],
    allowedHosts: [],
  });
});

test('executor grant adds only canonical real HTTPS enterprise hosts when configured', () => {
  assert.deepEqual(executorDelegationGrantRequest('z:tenant:privacy-guard', '0.4.3', {
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
    contractVersion: '0.4.3',
    numericContractId: 42,
    updatedAt: '2026-09-17T15:00:00.000Z',
  };

  assert.equal(provisioningStateMatches(state, {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.3',
  }), true);
  assert.equal(provisioningStateMatches(state, {
    tenantDid: 'did:t3n:other',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.3',
  }), false);
  assert.equal(provisioningStateMatches(state, {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.5.0',
  }), false);
});

test('remote provisioning state parser accepts only the minimal validated state shape', () => {
  const state = {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.3',
    numericContractId: 77,
    updatedAt: '2026-09-17T15:10:00.000Z',
  };
  assert.equal(parseProvisioningState(JSON.stringify(state))?.numericContractId, 77);
  assert.equal(parseProvisioningState(JSON.stringify({ ...state, secret: 'must-not-be-accepted' })), null);
  assert.equal(parseProvisioningState('{"numericContractId":0}'), null);
  assert.equal(parseProvisioningState('{not-json'), null);
});

test('numeric id selection prefers explicit config, then matching local cache, then matching remote state', () => {
  const expected = {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.3',
  };
  const local = { ...expected, numericContractId: 41, updatedAt: '2026-09-17T15:00:00.000Z' };
  const remote = { ...expected, numericContractId: 42, updatedAt: '2026-09-17T15:01:00.000Z' };

  assert.equal(reusableNumericContractId(40, local, remote, expected), 40);
  assert.equal(reusableNumericContractId(null, local, remote, expected), 41);
  assert.equal(reusableNumericContractId(null, null, remote, expected), 42);
  assert.equal(reusableNumericContractId(null, null, null, expected), null);
});

test('numeric id selection rejects remote state from another tenant, contract or version', () => {
  const expected = {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.3',
  };
  assert.throws(
    () => reusableNumericContractId(null, null, {
      ...expected,
      tenantDid: 'did:t3n:other',
      numericContractId: 42,
      updatedAt: '2026-09-17T15:01:00.000Z',
    }, expected),
    /does not match/,
  );
});

test('same-version reuse recovers numeric id from remote T3N state when local cache is absent', async () => {
  const directory = await mkdtemp(join(tmpdir(), 't3pg-runtime-state-'));
  const statePath = join(directory, 'missing-cache.json');
  const expected = {
    tenantDid: 'did:t3n:tenant123',
    contractId: 'z:tenant123:privacy-guard',
    contractVersion: '0.4.3',
  };
  const remoteState: RuntimeProvisioningState = {
    ...expected,
    numericContractId: 77,
    updatedAt: '2026-09-17T15:10:00.000Z',
  };
  const persistedRemote: RuntimeProvisioningState[] = [];

  try {
    const result = await resolveOrRegisterContract(
      { contractVersion: '0.4.3' } as unknown as Parameters<typeof resolveOrRegisterContract>[0],
      { getTenantDid: () => expected.tenantDid } as unknown as Parameters<typeof resolveOrRegisterContract>[1],
      {
        canonicalContractId: async () => expected.contractId,
        identity: async () => ({ contractId: expected.contractId, contractVersion: expected.contractVersion }),
      } as unknown as Parameters<typeof resolveOrRegisterContract>[2],
      { T3N_RUNTIME_PROVISIONING_STATE_PATH: statePath },
      {
        readRemoteProvisioningState: async () => remoteState,
        persistRemoteProvisioningState: async (state) => { persistedRemote.push(state); },
      },
    );

    assert.equal(result.numericContractId, 77);
    assert.equal(result.registered, false);
    assert.equal(persistedRemote[0]?.numericContractId, 77);
    const cached = parseProvisioningState(await readFile(statePath, 'utf8'));
    assert.equal(cached?.numericContractId, 77);
    assert.equal(cached?.contractVersion, '0.4.3');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('new registration persists numeric id before post-registration identity verification', async () => {
  const directory = await mkdtemp(join(tmpdir(), 't3pg-register-state-'));
  const statePath = join(directory, 'runtime-state.json');
  const wasmPath = join(directory, 'privacy-guard.wasm');
  const tenantDid = 'did:t3n:tenant123';
  const contractId = 'z:tenant123:privacy-guard';
  let identityCalls = 0;
  let registerCalls = 0;
  let remotePersistCalls = 0;

  try {
    await writeFile(wasmPath, new Uint8Array([0, 97, 115, 109]));
    await assert.rejects(
      () => resolveOrRegisterContract(
        { contractTail: 'privacy-guard', contractVersion: '0.4.3' } as unknown as Parameters<typeof resolveOrRegisterContract>[0],
        { getTenantDid: () => tenantDid } as unknown as Parameters<typeof resolveOrRegisterContract>[1],
        {
          canonicalContractId: async () => contractId,
          identity: async () => {
            identityCalls += 1;
            if (identityCalls === 1) return { contractId, contractVersion: '0.4.2' };
            throw new Error('post-register identity unavailable');
          },
        } as unknown as Parameters<typeof resolveOrRegisterContract>[2],
        {
          T3N_RUNTIME_PROVISIONING_STATE_PATH: statePath,
          T3N_CONTRACT_WASM_PATH: wasmPath,
        },
        {
          registerContract: async (request) => {
            registerCalls += 1;
            assert.equal(request.tail, 'privacy-guard');
            assert.equal(request.version, '0.4.3');
            return { contract_id: 88 };
          },
          persistRemoteProvisioningState: async () => { remotePersistCalls += 1; },
        },
      ),
      /post-register identity unavailable/,
    );

    assert.equal(registerCalls, 1);
    assert.equal(remotePersistCalls, 0);
    const cachedAfterFailure = parseProvisioningState(await readFile(statePath, 'utf8'));
    assert.equal(cachedAfterFailure?.tenantDid, tenantDid);
    assert.equal(cachedAfterFailure?.contractId, contractId);
    assert.equal(cachedAfterFailure?.contractVersion, '0.4.3');
    assert.equal(cachedAfterFailure?.numericContractId, 88);

    const persistedRemote: RuntimeProvisioningState[] = [];
    const recovered = await resolveOrRegisterContract(
      { contractTail: 'privacy-guard', contractVersion: '0.4.3' } as unknown as Parameters<typeof resolveOrRegisterContract>[0],
      { getTenantDid: () => tenantDid } as unknown as Parameters<typeof resolveOrRegisterContract>[1],
      {
        canonicalContractId: async () => contractId,
        identity: async () => ({ contractId, contractVersion: '0.4.3' }),
      } as unknown as Parameters<typeof resolveOrRegisterContract>[2],
      { T3N_RUNTIME_PROVISIONING_STATE_PATH: statePath },
      {
        registerContract: async () => { throw new Error('same version must not register again'); },
        persistRemoteProvisioningState: async (state) => { persistedRemote.push(state); },
      },
    );

    assert.equal(recovered.registered, false);
    assert.equal(recovered.numericContractId, 88);
    assert.equal(persistedRemote[0]?.numericContractId, 88);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('same-version reuse fails closed when env, local cache and remote T3N state cannot supply the numeric id', async () => {
  const directory = await mkdtemp(join(tmpdir(), 't3pg-runtime-state-'));
  try {
    await assert.rejects(
      () => resolveOrRegisterContract(
        { contractVersion: '0.4.3' } as unknown as Parameters<typeof resolveOrRegisterContract>[0],
        { getTenantDid: () => 'did:t3n:tenant123' } as unknown as Parameters<typeof resolveOrRegisterContract>[1],
        {
          canonicalContractId: async () => 'z:tenant123:privacy-guard',
          identity: async () => ({ contractId: 'z:tenant123:privacy-guard', contractVersion: '0.4.3' }),
        } as unknown as Parameters<typeof resolveOrRegisterContract>[2],
        { T3N_RUNTIME_PROVISIONING_STATE_PATH: join(directory, 'missing.json') },
        {
          readRemoteProvisioningState: async () => null,
          persistRemoteProvisioningState: async () => undefined,
        },
      ),
      /Numeric T3N contract id is unavailable/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
