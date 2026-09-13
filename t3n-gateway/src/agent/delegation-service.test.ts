import assert from 'node:assert/strict';
import test from 'node:test';
import type { T3nSession } from '../t3n/session.js';
import type { AgentSession } from './agent-session.js';
import {
  DelegationService,
  EXECUTOR_DELEGATION_REQUIREMENTS,
  PROPOSAL_DELEGATION_REQUIREMENTS,
  interpretDelegationWindow,
} from './delegation-service.js';

interface FakeOptions {
  readonly authorised?: boolean;
  readonly checkResult?: unknown;
  readonly checkError?: Error;
  readonly principalDid?: string;
}

function fakeSessions(policy: unknown, options: FakeOptions = {}) {
  const updates: unknown[] = [];
  const checks: unknown[] = [];
  let tenantCheckCalled = false;
  const tenant = {
    connect: async () => undefined,
    getTenantDid: () => 'did:t3n:tenant-test',
    getClient: () => ({
      getMemberDelegation: async () => policy,
      updateMemberDelegation: async (value: unknown) => { updates.push(value); },
      checkDelegation: async () => { tenantCheckCalled = true; throw new Error('Tenant client must not perform delegated principal checks'); },
    }),
  } as unknown as T3nSession;
  const agent = {
    connect: async () => undefined,
    getAgentDid: () => options.principalDid ?? 'did:t3n:agent-test',
    getClient: () => ({
      checkDelegation: async (value: unknown) => {
        checks.push(value);
        if (options.checkError) throw options.checkError;
        if ('checkResult' in options) return options.checkResult;
        return { authorised: options.authorised ?? true, satisfied: [], missing: [] };
      },
    }),
  } as unknown as AgentSession;
  return { tenant, agent, updates, checks, tenantCheckCalled: () => tenantCheckCalled };
}

function activeGrant(grantee = 'did:t3n:agent-test') {
  return {
    grants: [{
      grantee,
      contract_id: 'z:tenant:privacy-guard',
      functions: ['evaluate-action'],
      scopes: ['incident_id', 'credential_id', 'reason'],
      allowed_hosts: [],
    }],
  };
}

test('interprets delegation validity window fail-closed at exact temporal boundaries', () => {
  const now = 1_700_000_000;
  assert.equal(interpretDelegationWindow(undefined, now), 'ACTIVE');
  assert.equal(interpretDelegationWindow({ valid_from_secs: now }, now), 'ACTIVE');
  assert.equal(interpretDelegationWindow({ valid_until_secs: now }, now), 'ACTIVE');
  assert.equal(interpretDelegationWindow({ valid_from_secs: now + 1 }, now), 'SCHEDULED');
  assert.equal(interpretDelegationWindow({ valid_until_secs: now - 1 }, now), 'REVOKED');
  assert.equal(interpretDelegationWindow({ valid_from_secs: now + 10, valid_until_secs: now + 5 }, now), 'UNKNOWN');
  assert.equal(interpretDelegationWindow({ valid_from_secs: 'later' }, now), 'UNKNOWN');
  assert.equal(interpretDelegationWindow({ valid_until_secs: Number.NaN }, now), 'UNKNOWN');
  assert.equal(interpretDelegationWindow('invalid', now), 'UNKNOWN');
});

test('confirms effective access only when ACTIVE member grant and principal check both succeed', async () => {
  const fake = fakeSessions(activeGrant(), { authorised: true });
  const service = new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  const result = await service.status('z:tenant:privacy-guard');

  assert.equal(result.memberState, 'ACTIVE');
  assert.equal(result.effectiveState, 'ACTIVE');
  assert.deepEqual(result.functions, ['evaluate-action']);
  assert.deepEqual(result.scopes, ['incident_id', 'credential_id', 'reason']);
  assert.deepEqual(result.checkedFunctions, ['evaluate-action']);
  assert.deepEqual(result.checkedScopes, ['incident_id', 'credential_id', 'reason']);
  assert.deepEqual(fake.checks, [{
    contract: 'z:tenant:privacy-guard',
    pii_did: 'did:t3n:tenant-test',
    functions: ['evaluate-action'],
    scopes: ['incident_id', 'credential_id', 'reason'],
  }]);
  assert.equal(fake.tenantCheckCalled(), false);
});

test('reports DENIED when the authenticated principal check returns authorised=false', async () => {
  const fake = fakeSessions(activeGrant(), { authorised: false });
  const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'ACTIVE');
  assert.equal(result.effectiveState, 'DENIED');
  assert.equal(fake.checks.length, 1);
});

test('reports UNKNOWN when checkDelegation fails or returns an inconclusive payload', async () => {
  for (const options of [{ checkError: new Error('timeout') }, { checkResult: {} }]) {
    const fake = fakeSessions(activeGrant(), options);
    const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
    assert.equal(result.memberState, 'ACTIVE');
    assert.equal(result.effectiveState, 'UNKNOWN');
    assert.equal(fake.checks.length, 1);
  }
});

test('reports NOT_GRANTED without issuing a positive delegated-principal check', async () => {
  const fake = fakeSessions({ grants: [] }, { authorised: true });
  const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'NOT_GRANTED');
  assert.equal(result.effectiveState, 'DENIED');
  assert.deepEqual(result.checkedFunctions, []);
  assert.deepEqual(result.checkedScopes, []);
  assert.equal(fake.checks.length, 0);
});

test('reports SCHEDULED without issuing checkDelegation before the grant is active', async () => {
  const now = Math.floor(Date.now() / 1000);
  const fake = fakeSessions({ grants: [{
    grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', functions: ['evaluate-action'], scopes: ['incident_id'],
    window: { valid_from_secs: now + 300, valid_until_secs: now + 600 },
  }] }, { authorised: true });
  const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'SCHEDULED');
  assert.equal(result.effectiveState, 'DENIED');
  assert.deepEqual(result.checkedFunctions, []);
  assert.deepEqual(result.checkedScopes, []);
  assert.equal(fake.checks.length, 0);
});

test('reports REVOKED without issuing checkDelegation after the Member grant expired', async () => {
  const now = Math.floor(Date.now() / 1000);
  const fake = fakeSessions({ grants: [{
    grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', functions: ['evaluate-action'], scopes: ['incident_id'],
    window: { valid_until_secs: now - 1 },
  }] }, { authorised: true });
  const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'REVOKED');
  assert.equal(result.effectiveState, 'DENIED');
  assert.deepEqual(result.checkedFunctions, []);
  assert.deepEqual(result.checkedScopes, []);
  assert.equal(fake.checks.length, 0);
});

test('reports UNKNOWN for unreadable grant without issuing a potentially misleading platform check', async () => {
  const now = Math.floor(Date.now() / 1000);
  const fake = fakeSessions({ grants: [{
    grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', functions: ['evaluate-action'], scopes: ['incident_id'],
    window: { valid_from_secs: now + 600, valid_until_secs: now + 300 },
  }] }, { authorised: true });
  const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'UNKNOWN');
  assert.equal(result.effectiveState, 'UNKNOWN');
  assert.deepEqual(result.checkedFunctions, []);
  assert.deepEqual(result.checkedScopes, []);
  assert.equal(fake.checks.length, 0);
});

test('proposal and executor checks use independent principal clients and exact least-privilege requirements', async () => {
  const proposal = fakeSessions(activeGrant('did:t3n:proposal'), { authorised: true, principalDid: 'did:t3n:proposal' });
  const executor = fakeSessions({ grants: [{
    grantee: 'did:t3n:executor', contract_id: 'z:tenant:privacy-guard',
    functions: ['execute-remediation', 'verify-remediation'], scopes: ['incident_id', 'credential_id', 'reason'],
    allowed_hosts: ['security.example'],
  }] }, { authorised: true, principalDid: 'did:t3n:executor' });

  const proposalResult = await new DelegationService(proposal.tenant, proposal.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
  const executorResult = await new DelegationService(executor.tenant, executor.agent, EXECUTOR_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');

  assert.equal(proposalResult.effectiveState, 'ACTIVE');
  assert.equal(executorResult.effectiveState, 'ACTIVE');
  assert.deepEqual(proposal.checks[0], {
    contract: 'z:tenant:privacy-guard', pii_did: 'did:t3n:tenant-test', functions: ['evaluate-action'], scopes: ['incident_id', 'credential_id', 'reason'],
  });
  assert.deepEqual(executor.checks[0], {
    contract: 'z:tenant:privacy-guard', pii_did: 'did:t3n:tenant-test', functions: ['execute-remediation', 'verify-remediation'], scopes: ['incident_id', 'credential_id', 'reason'],
  });
});

test('constructor rejects wildcard requirements', () => {
  const fake = fakeSessions({ grants: [] });
  assert.throws(() => new DelegationService(fake.tenant, fake.agent, { functions: ['*'], scopes: ['incident_id'] }), /wildcard/);
  assert.throws(() => new DelegationService(fake.tenant, fake.agent, { functions: ['evaluate-action'], scopes: ['*'] }), /wildcard/);
});

test('revoke returns NOT_GRANTED without writing a replacement policy when grant is absent', async () => {
  const fake = fakeSessions({ grants: [] });
  const service = new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  assert.equal(await service.revoke('z:tenant:privacy-guard'), 'NOT_GRANTED');
  assert.equal(fake.updates.length, 0);
});

test('revoke expires only the matching grant and preserves its original restrictions', async () => {
  const fake = fakeSessions({ grants: [{
    grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', version_req: '0.4.0',
    functions: ['evaluate-action'], scopes: ['incident_id', 'credential_id', 'reason'], allowed_hosts: [], read_scopes: ['incident_id'],
  }] });
  const service = new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  assert.equal(await service.revoke('z:tenant:privacy-guard'), 'REVOKED');
  assert.equal(fake.updates.length, 1);
  const update = fake.updates[0] as Record<string, unknown>;
  assert.deepEqual(update.functions, ['evaluate-action']);
  assert.deepEqual(update.scopes, ['incident_id', 'credential_id', 'reason']);
  assert.deepEqual(update.allowed_hosts, []);
  assert.ok((update.window as { valid_until_secs: number }).valid_until_secs < Math.floor(Date.now() / 1000));
});

test('grant forwards only the declared function, scope and host restrictions', async () => {
  const fake = fakeSessions({ grants: [] });
  const service = new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  await service.grant({ contractId: 'z:tenant:privacy-guard', versionReq: '0.4.0', functions: ['evaluate-action'], scopes: ['incident_id'], allowedHosts: [] });
  assert.equal(fake.updates.length, 1);
  assert.deepEqual(fake.updates[0], {
    grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', version_req: '0.4.0', functions: ['evaluate-action'], scopes: ['incident_id'], read_scopes: undefined, allowed_hosts: [], window: undefined,
  });
});
