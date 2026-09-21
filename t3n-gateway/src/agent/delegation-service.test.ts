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
  readonly checkResults?: readonly unknown[];
  readonly checkError?: Error;
  readonly principalDid?: string;
}

function fakeSessions(policy: unknown, options: FakeOptions = {}) {
  const updates: unknown[] = [];
  const checks: unknown[] = [];
  let checkIndex = 0;
  let tenantCheckCalled = false;
  const tenant = {
    connect: async () => undefined,
    getTenantDid: () => 'did:t3n:tenant-test',
    getClient: () => ({
      getMemberDelegation: async () => policy,
      updateMemberDelegation: async (value: unknown) => { updates.push(value); },
      checkDelegation: async () => {
        tenantCheckCalled = true;
        throw new Error('Tenant client must not perform delegated principal checks');
      },
    }),
  } as unknown as T3nSession;
  const agent = {
    connect: async () => undefined,
    getAgentDid: () => options.principalDid ?? 'did:t3n:agent-test',
    getClient: () => ({
      checkDelegation: async (value: unknown) => {
        checks.push(value);
        if (options.checkError) throw options.checkError;
        if (options.checkResults) return options.checkResults[checkIndex++];
        return { authorised: options.authorised ?? true, satisfied: [], missing: [] };
      },
    }),
  } as unknown as AgentSession;
  return { tenant, agent, updates, checks, tenantCheckCalled: () => tenantCheckCalled };
}

function proposalGrant(grantee = 'did:t3n:agent-test') {
  return {
    grantee,
    contract_id: 'z:tenant:privacy-guard',
    functions: ['evaluate-action'],
    scopes: ['incident_id', 'credential_id', 'reason'],
    allowed_hosts: [],
  };
}

function executorGrants(grantee = 'did:t3n:executor') {
  return [
    {
      grantee,
      contract_id: 'z:tenant:privacy-guard',
      functions: ['execute-remediation'],
      scopes: ['incident_id', 'credential_id', 'reason', 'verified_contacts.email.value'],
      allowed_hosts: ['security.example'],
    },
    {
      grantee,
      contract_id: 'z:tenant:privacy-guard',
      functions: ['verify-remediation'],
      scopes: ['incident_id', 'credential_id', 'reason'],
      allowed_hosts: ['verify.example'],
    },
  ];
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

test('grant writes exactly one function and never sends the removed read_scopes field', async () => {
  const fake = fakeSessions({ grants: [] });
  const service = new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS);

  await service.grant({
    contractId: 'z:tenant:privacy-guard',
    versionReq: '0.4.5',
    function: 'evaluate-action',
    scopes: ['incident_id', 'credential_id', 'reason'],
    allowedHosts: [],
  });

  assert.equal(fake.updates.length, 1);
  assert.deepEqual(fake.updates[0], {
    grantee: 'did:t3n:agent-test',
    contract_id: 'z:tenant:privacy-guard',
    version_req: '0.4.5',
    functions: ['evaluate-action'],
    scopes: ['incident_id', 'credential_id', 'reason'],
    allowed_hosts: [],
    window: undefined,
  });
  assert.equal('read_scopes' in (fake.updates[0] as Record<string, unknown>), false);
});

test('proposal status confirms the exact single-function grant with the delegated principal', async () => {
  const fake = fakeSessions({ grants: [proposalGrant()] }, { authorised: true });
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

test('executor status verifies each function independently under per-function keying', async () => {
  const fake = fakeSessions(
    { grants: executorGrants() },
    { authorised: true, principalDid: 'did:t3n:executor' },
  );
  const result = await new DelegationService(
    fake.tenant,
    fake.agent,
    EXECUTOR_DELEGATION_REQUIREMENTS,
  ).status('z:tenant:privacy-guard');

  assert.equal(result.memberState, 'ACTIVE');
  assert.equal(result.effectiveState, 'ACTIVE');
  assert.deepEqual(result.functions, ['execute-remediation', 'verify-remediation']);
  assert.deepEqual(fake.checks, [
    {
      contract: 'z:tenant:privacy-guard',
      pii_did: 'did:t3n:tenant-test',
      functions: ['execute-remediation'],
      scopes: ['incident_id', 'credential_id', 'reason', 'verified_contacts.email.value'],
    },
    {
      contract: 'z:tenant:privacy-guard',
      pii_did: 'did:t3n:tenant-test',
      functions: ['verify-remediation'],
      scopes: ['incident_id', 'credential_id', 'reason'],
    },
  ]);
});

test('one denied function makes aggregate effective access DENIED', async () => {
  const fake = fakeSessions(
    { grants: executorGrants() },
    {
      principalDid: 'did:t3n:executor',
      checkResults: [{ authorised: true }, { authorised: false }],
    },
  );
  const result = await new DelegationService(fake.tenant, fake.agent, EXECUTOR_DELEGATION_REQUIREMENTS)
    .status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'ACTIVE');
  assert.equal(result.effectiveState, 'DENIED');
  assert.equal(fake.checks.length, 2);
});

test('missing one required per-function grant is NOT_GRANTED and skips platform checks', async () => {
  const [executeGrant] = executorGrants();
  const fake = fakeSessions(
    { grants: [executeGrant] },
    { principalDid: 'did:t3n:executor', authorised: true },
  );
  const result = await new DelegationService(fake.tenant, fake.agent, EXECUTOR_DELEGATION_REQUIREMENTS)
    .status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'NOT_GRANTED');
  assert.equal(result.effectiveState, 'DENIED');
  assert.equal(fake.checks.length, 0);
});

test('legacy multi-function grants remain fail-closed instead of being accepted as current state', async () => {
  const fake = fakeSessions({
    grants: [{
      grantee: 'did:t3n:executor',
      contract_id: 'z:tenant:privacy-guard',
      functions: ['execute-remediation', 'verify-remediation'],
      scopes: ['incident_id', 'credential_id', 'reason', 'verified_contacts.email.value'],
      allowed_hosts: ['security.example', 'verify.example'],
    }],
  }, { principalDid: 'did:t3n:executor', authorised: true });

  const result = await new DelegationService(fake.tenant, fake.agent, EXECUTOR_DELEGATION_REQUIREMENTS)
    .status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'UNKNOWN');
  assert.equal(result.effectiveState, 'UNKNOWN');
  assert.equal(fake.checks.length, 0);
});

test('extra separately-granted function fails closed instead of widening least privilege', async () => {
  const fake = fakeSessions({
    grants: [
      proposalGrant(),
      {
        ...proposalGrant(),
        functions: ['execute-remediation'],
      },
    ],
  }, { authorised: true });

  const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS)
    .status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'UNKNOWN');
  assert.equal(result.effectiveState, 'UNKNOWN');
  assert.equal(fake.checks.length, 0);
});

test('wildcard function is recognized on read but is never accepted as least-privilege readiness', async () => {
  const fake = fakeSessions({
    grants: [{
      ...proposalGrant(),
      functions: ['*'],
    }],
  }, { authorised: true });

  const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS)
    .status('z:tenant:privacy-guard');
  assert.deepEqual(result.functions, ['*']);
  assert.equal(result.memberState, 'UNKNOWN');
  assert.equal(result.effectiveState, 'UNKNOWN');
  assert.equal(fake.checks.length, 0);
});

test('structured scopes require both path and access and are aggregated by path', async () => {
  const fake = fakeSessions({
    grants: [{
      ...proposalGrant(),
      scopes: [
        { path: 'incident_id', access: 'read' },
        { path: 'credential_id', access: 'read' },
        { path: 'reason', access: 'read' },
      ],
    }],
  }, { authorised: true });

  const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS)
    .status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'ACTIVE');
  assert.equal(result.effectiveState, 'ACTIVE');
  assert.deepEqual(result.scopes, ['incident_id', 'credential_id', 'reason']);
});

test('structured scope without access fails closed', async () => {
  const fake = fakeSessions({
    grants: [{
      ...proposalGrant(),
      scopes: [
        { path: 'incident_id', access: 'read' },
        { path: 'credential_id' },
        { path: 'reason', access: 'read' },
      ],
    }],
  }, { authorised: true });

  const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS)
    .status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'UNKNOWN');
  assert.equal(result.effectiveState, 'UNKNOWN');
  assert.equal(fake.checks.length, 0);
});

test('overbroad or incomplete function scopes fail closed before checkDelegation', async () => {
  for (const scopes of [
    ['incident_id', 'credential_id'],
    ['incident_id', 'credential_id', 'reason', 'extra'],
  ]) {
    const fake = fakeSessions({ grants: [{ ...proposalGrant(), scopes }] }, { authorised: true });
    const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS)
      .status('z:tenant:privacy-guard');
    assert.equal(result.memberState, 'UNKNOWN');
    assert.equal(result.effectiveState, 'UNKNOWN');
    assert.equal(fake.checks.length, 0);
  }
});

test('known non-active grant states skip potentially misleading positive platform checks', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const [window, expected] of [
    [{ valid_from_secs: now + 300, valid_until_secs: now + 600 }, 'SCHEDULED'],
    [{ valid_until_secs: now - 1 }, 'REVOKED'],
  ] as const) {
    const fake = fakeSessions({ grants: [{ ...proposalGrant(), window }] }, { authorised: true });
    const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS)
      .status('z:tenant:privacy-guard');
    assert.equal(result.memberState, expected);
    assert.equal(result.effectiveState, 'DENIED');
    assert.equal(fake.checks.length, 0);
  }
});

test('inconclusive delegated-principal verdict remains UNKNOWN', async () => {
  for (const options of [
    { checkError: new Error('timeout') },
    { checkResults: [{}] },
  ]) {
    const fake = fakeSessions({ grants: [proposalGrant()] }, options);
    const result = await new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS)
      .status('z:tenant:privacy-guard');
    assert.equal(result.memberState, 'ACTIVE');
    assert.equal(result.effectiveState, 'UNKNOWN');
  }
});

test('constructor and grant reject wildcard provisioning', async () => {
  const fake = fakeSessions({ grants: [] });
  assert.throws(
    () => new DelegationService(fake.tenant, fake.agent, {
      grants: [{ function: '*', scopes: ['incident_id'] }],
      functions: ['*'],
      scopes: ['incident_id'],
    }),
    /wildcard/,
  );

  const service = new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  await assert.rejects(
    () => service.grant({
      contractId: 'z:tenant:privacy-guard',
      function: '*',
      scopes: ['incident_id'],
    }),
    /wildcard/,
  );
});

test('revoke expires every matching single-function grant independently without read_scopes', async () => {
  const fake = fakeSessions(
    { grants: executorGrants() },
    { principalDid: 'did:t3n:executor' },
  );
  const service = new DelegationService(fake.tenant, fake.agent, EXECUTOR_DELEGATION_REQUIREMENTS);

  assert.equal(await service.revoke('z:tenant:privacy-guard'), 'REVOKED');
  assert.equal(fake.updates.length, 2);
  for (const update of fake.updates as Array<Record<string, unknown>>) {
    assert.equal(Array.isArray(update.functions), true);
    assert.equal((update.functions as string[]).length, 1);
    assert.equal('read_scopes' in update, false);
    assert.deepEqual(update.window && Object.keys(update.window as object), ['valid_until_secs']);
  }
});

test('revoke refuses legacy multi-function grant because it cannot be safely keyed', async () => {
  const fake = fakeSessions({
    grants: [{
      grantee: 'did:t3n:agent-test',
      contract_id: 'z:tenant:privacy-guard',
      functions: ['evaluate-action', 'verify-remediation'],
      scopes: ['incident_id', 'credential_id', 'reason'],
    }],
  });
  const service = new DelegationService(fake.tenant, fake.agent, PROPOSAL_DELEGATION_REQUIREMENTS);
  await assert.rejects(() => service.revoke('z:tenant:privacy-guard'), /function-scoped grant/);
  assert.equal(fake.updates.length, 0);
});
