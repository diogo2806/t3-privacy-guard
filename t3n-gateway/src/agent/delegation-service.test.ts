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

interface FakeSessionOptions {
  readonly principalDid?: string;
  readonly tenantDid?: string;
  readonly checkResult?: unknown;
  readonly checkError?: Error;
}

function fakeSessions(policy: unknown, options: FakeSessionOptions = {}) {
  const updates: unknown[] = [];
  const checkCalls: unknown[] = [];
  const tenantCheckCalls: unknown[] = [];
  const tenantDid = options.tenantDid ?? 'did:t3n:tenant-test';
  const principalDid = options.principalDid ?? 'did:t3n:agent-test';
  const tenant = {
    connect: async () => undefined,
    getTenantDid: () => tenantDid,
    getClient: () => ({
      getMemberDelegation: async () => policy,
      updateMemberDelegation: async (value: unknown) => { updates.push(value); },
      checkDelegation: async (value: unknown) => {
        tenantCheckCalls.push(value);
        throw new Error('Tenant client must not perform the effective delegation check');
      },
    }),
  } as unknown as T3nSession;
  const agent = {
    connect: async () => undefined,
    getAgentDid: () => principalDid,
    getClient: () => ({
      checkDelegation: async (value: unknown) => {
        checkCalls.push(value);
        if (options.checkError) throw options.checkError;
        return options.checkResult ?? { authorised: true, satisfied: [], missing: [] };
      },
    }),
  } as unknown as AgentSession;
  return { tenant, agent, updates, checkCalls, tenantCheckCalls };
}

function activeGrant(principalDid = 'did:t3n:agent-test') {
  return {
    grants: [{
      grantee: principalDid,
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

test('confirms effective access only from the authenticated principal checkDelegation client', async () => {
  const { tenant, agent, checkCalls, tenantCheckCalls } = fakeSessions(activeGrant(), {
    tenantDid: 'did:t3n:canonical-tenant',
    checkResult: { authorised: true, satisfied: ['evaluate-action'], missing: [] },
  });
  const service = new DelegationService(tenant, agent, PROPOSAL_DELEGATION_REQUIREMENTS);

  const result = await service.status('z:tenant:privacy-guard');

  assert.equal(result.memberState, 'ACTIVE');
  assert.equal(result.effectiveState, 'ACTIVE');
  assert.deepEqual(result.checkedFunctions, ['evaluate-action']);
  assert.deepEqual(result.checkedScopes, ['incident_id', 'credential_id', 'reason']);
  assert.deepEqual(checkCalls, [{
    contract: 'z:tenant:privacy-guard',
    pii_did: 'did:t3n:canonical-tenant',
    functions: ['evaluate-action'],
    scopes: ['incident_id', 'credential_id', 'reason'],
  }]);
  assert.equal(tenantCheckCalls.length, 0);
  assert.equal('policy' in result, false);
});

test('maps authorised=false to DENIED even when the Member grant is ACTIVE', async () => {
  const { tenant, agent } = fakeSessions(activeGrant(), { checkResult: { authorised: false, missing: ['evaluate-action'] } });
  const service = new DelegationService(tenant, agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  const result = await service.status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'ACTIVE');
  assert.equal(result.effectiveState, 'DENIED');
});

test('maps checkDelegation errors and inconclusive payloads to UNKNOWN', async () => {
  const failing = fakeSessions(activeGrant(), { checkError: new Error('network timeout') });
  const failingResult = await new DelegationService(failing.tenant, failing.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
  assert.equal(failingResult.memberState, 'ACTIVE');
  assert.equal(failingResult.effectiveState, 'UNKNOWN');

  const inconclusive = fakeSessions(activeGrant(), { checkResult: { satisfied: [], missing: [] } });
  const inconclusiveResult = await new DelegationService(inconclusive.tenant, inconclusive.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
  assert.equal(inconclusiveResult.effectiveState, 'UNKNOWN');
});

test('does not perform a positive effective check for NOT_GRANTED, SCHEDULED, REVOKED or malformed grants', async () => {
  const now = Math.floor(Date.now() / 1000);
  const policies = [
    { expected: 'NOT_GRANTED', value: { grants: [] } },
    { expected: 'SCHEDULED', value: { grants: [{ ...activeGrant().grants[0], window: { valid_from_secs: now + 300 } }] } },
    { expected: 'REVOKED', value: { grants: [{ ...activeGrant().grants[0], window: { valid_until_secs: now - 1 } }] } },
    { expected: 'UNKNOWN', value: { grants: [{ ...activeGrant().grants[0], functions: [] }] } },
  ];

  for (const entry of policies) {
    const { tenant, agent, checkCalls } = fakeSessions(entry.value);
    const result = await new DelegationService(tenant, agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
    assert.equal(result.memberState, entry.expected);
    assert.equal(result.effectiveState, entry.expected === 'UNKNOWN' ? 'UNKNOWN' : 'DENIED');
    assert.equal(checkCalls.length, 0);
    assert.deepEqual(result.checkedFunctions, []);
    assert.deepEqual(result.checkedScopes, []);
  }
});

test('proposal and executor checks remain independent and use exact least-privilege functions', async () => {
  const proposal = fakeSessions(activeGrant('did:t3n:proposal'), { principalDid: 'did:t3n:proposal' });
  const executorPolicy = {
    grants: [{
      grantee: 'did:t3n:executor',
      contract_id: 'z:tenant:privacy-guard',
      functions: ['execute-remediation', 'verify-remediation'],
      scopes: ['incident_id', 'credential_id', 'reason'],
      allowed_hosts: ['security.example'],
    }],
  };
  const executor = fakeSessions(executorPolicy, { principalDid: 'did:t3n:executor' });

  const proposalStatus = await new DelegationService(proposal.tenant, proposal.agent, PROPOSAL_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');
  const executorStatus = await new DelegationService(executor.tenant, executor.agent, EXECUTOR_DELEGATION_REQUIREMENTS).status('z:tenant:privacy-guard');

  assert.equal(proposalStatus.effectiveState, 'ACTIVE');
  assert.equal(executorStatus.effectiveState, 'ACTIVE');
  assert.deepEqual((proposal.checkCalls[0] as { functions: string[] }).functions, ['evaluate-action']);
  assert.deepEqual((executor.checkCalls[0] as { functions: string[] }).functions, ['execute-remediation', 'verify-remediation']);
});

test('revoke returns NOT_GRANTED without writing a replacement policy when grant is absent', async () => {
  const { tenant, agent, updates } = fakeSessions({ grants: [] });
  const service = new DelegationService(tenant, agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  assert.equal(await service.revoke('z:tenant:privacy-guard'), 'NOT_GRANTED');
  assert.equal(updates.length, 0);
});

test('revoke expires only the matching grant and preserves its original restrictions', async () => {
  const { tenant, agent, updates } = fakeSessions({ grants: [{ grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', version_req: '0.4.0', functions: ['evaluate-action'], scopes: ['incident_id', 'credential_id', 'reason'], allowed_hosts: [], read_scopes: ['incident_id'] }] });
  const service = new DelegationService(tenant, agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  assert.equal(await service.revoke('z:tenant:privacy-guard'), 'REVOKED');
  assert.equal(updates.length, 1);
  const update = updates[0] as Record<string, unknown>;
  assert.deepEqual(update.functions, ['evaluate-action']);
  assert.deepEqual(update.scopes, ['incident_id', 'credential_id', 'reason']);
  assert.deepEqual(update.allowed_hosts, []);
  assert.ok((update.window as { valid_until_secs: number }).valid_until_secs < Math.floor(Date.now() / 1000));
});

test('grant forwards only the declared function, scope and host restrictions', async () => {
  const { tenant, agent, updates } = fakeSessions({ grants: [] });
  const service = new DelegationService(tenant, agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  await service.grant({ contractId: 'z:tenant:privacy-guard', versionReq: '0.4.0', functions: ['evaluate-action'], scopes: ['incident_id'], allowedHosts: [] });
  assert.equal(updates.length, 1);
  assert.deepEqual(updates[0], {
    grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', version_req: '0.4.0', functions: ['evaluate-action'], scopes: ['incident_id'], read_scopes: undefined, allowed_hosts: [], window: undefined,
  });
});
