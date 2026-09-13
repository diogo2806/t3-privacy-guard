import assert from 'node:assert/strict';
import test from 'node:test';
import type { T3nSession } from '../t3n/session.js';
import type { AgentSession } from './agent-session.js';
import { DelegationService, interpretDelegationWindow } from './delegation-service.js';

function fakeSessions(policy: unknown) {
  const updates: unknown[] = [];
  const tenant = {
    connect: async () => undefined,
    getClient: () => ({
      getMemberDelegation: async () => policy,
      updateMemberDelegation: async (value: unknown) => { updates.push(value); },
    }),
  } as unknown as T3nSession;
  const agent = {
    connect: async () => undefined,
    getAgentDid: () => 'did:t3n:agent-test',
  } as unknown as AgentSession;
  return { tenant, agent, updates };
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

test('reports NOT_GRANTED when no grant exists for agent and contract', async () => {
  const { tenant, agent } = fakeSessions({ grants: [] });
  const service = new DelegationService(tenant, agent);
  const result = await service.status('z:tenant:privacy-guard');
  assert.equal(result.state, 'NOT_GRANTED');
});

test('reports SCHEDULED for a matching grant whose validity window has not begun', async () => {
  const now = Math.floor(Date.now() / 1000);
  const { tenant, agent } = fakeSessions({
    grants: [{
      grantee: 'did:t3n:agent-test',
      contract_id: 'z:tenant:privacy-guard',
      functions: ['evaluate-action'],
      scopes: ['incident_id'],
      window: { valid_from_secs: now + 300, valid_until_secs: now + 600 },
    }],
  });
  const service = new DelegationService(tenant, agent);
  assert.equal((await service.status('z:tenant:privacy-guard')).state, 'SCHEDULED');
});

test('reports UNKNOWN for unreadable or inverted matching grant windows', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const window of [
    { valid_from_secs: 'later' },
    { valid_until_secs: 'later' },
    { valid_from_secs: now + 600, valid_until_secs: now + 300 },
  ]) {
    const { tenant, agent } = fakeSessions({
      grants: [{
        grantee: 'did:t3n:agent-test',
        contract_id: 'z:tenant:privacy-guard',
        functions: ['evaluate-action'],
        scopes: ['incident_id'],
        window,
      }],
    });
    const service = new DelegationService(tenant, agent);
    assert.equal((await service.status('z:tenant:privacy-guard')).state, 'UNKNOWN');
  }
});

test('revoke returns NOT_GRANTED without writing a replacement policy when grant is absent', async () => {
  const { tenant, agent, updates } = fakeSessions({ grants: [] });
  const service = new DelegationService(tenant, agent);
  assert.equal(await service.revoke('z:tenant:privacy-guard'), 'NOT_GRANTED');
  assert.equal(updates.length, 0);
});

test('revoke expires only the matching grant and preserves its original restrictions', async () => {
  const { tenant, agent, updates } = fakeSessions({
    grants: [{
      grantee: 'did:t3n:agent-test',
      contract_id: 'z:tenant:privacy-guard',
      version_req: '0.3.0',
      functions: ['evaluate-action', 'execute-remediation', 'verify-remediation'],
      scopes: ['incident_id', 'credential_id', 'reason'],
      allowed_hosts: ['security.example', 'verification.example'],
      read_scopes: ['incident_id'],
    }],
  });
  const service = new DelegationService(tenant, agent);

  assert.equal(await service.revoke('z:tenant:privacy-guard'), 'REVOKED');
  assert.equal(updates.length, 1);
  const update = updates[0] as Record<string, unknown>;
  assert.deepEqual(update.functions, ['evaluate-action', 'execute-remediation', 'verify-remediation']);
  assert.deepEqual(update.scopes, ['incident_id', 'credential_id', 'reason']);
  assert.deepEqual(update.allowed_hosts, ['security.example', 'verification.example']);
  assert.ok((update.window as { valid_until_secs: number }).valid_until_secs < Math.floor(Date.now() / 1000));
});

test('grant forwards only the declared function, scope and host restrictions', async () => {
  const { tenant, agent, updates } = fakeSessions({ grants: [] });
  const service = new DelegationService(tenant, agent);
  await service.grant({
    contractId: 'z:tenant:privacy-guard',
    versionReq: '0.3.0',
    functions: ['evaluate-action', 'verify-remediation'],
    scopes: ['incident_id'],
    allowedHosts: ['verification.example'],
  });

  assert.equal(updates.length, 1);
  assert.deepEqual(updates[0], {
    grantee: 'did:t3n:agent-test',
    contract_id: 'z:tenant:privacy-guard',
    version_req: '0.3.0',
    functions: ['evaluate-action', 'verify-remediation'],
    scopes: ['incident_id'],
    read_scopes: undefined,
    allowed_hosts: ['verification.example'],
    window: undefined,
  });
});
