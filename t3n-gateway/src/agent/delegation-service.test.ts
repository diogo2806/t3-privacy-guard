import assert from 'node:assert/strict';
import test from 'node:test';
import type { T3nSession } from '../t3n/session.js';
import type { AgentSession } from './agent-session.js';
import { DelegationService, interpretDelegationWindow } from './delegation-service.js';

interface Verdict { authorised?: boolean; satisfied?: unknown; missing?: unknown }

function fakeSessions(policy: unknown, verdict: Verdict | Error = { authorised: true, satisfied: ['member_delegation'], missing: [] }) {
  const updates: unknown[] = [];
  const checks: unknown[] = [];
  const tenant = {
    connect: async () => undefined,
    getTenantDid: () => 'did:t3n:tenant-test',
    getClient: () => ({
      getMemberDelegation: async () => policy,
      updateMemberDelegation: async (value: unknown) => { updates.push(value); },
    }),
  } as unknown as T3nSession;
  const agent = {
    connect: async () => undefined,
    getAgentDid: () => 'did:t3n:agent-test',
    getClient: () => ({
      checkDelegation: async (input: unknown) => {
        checks.push(input);
        if (verdict instanceof Error) throw verdict;
        return verdict;
      },
    }),
  } as unknown as AgentSession;
  return { tenant, agent, updates, checks };
}

function activePolicy() {
  return { grants: [{ grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', functions: ['evaluate-action'], scopes: ['incident_id'], allowed_hosts: ['security.example'] }] };
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

test('no member grant is incomplete and does not call platform delegation check', async () => {
  const { tenant, agent, checks } = fakeSessions({ grants: [] });
  const result = await new DelegationService(tenant, agent).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'NOT_GRANTED');
  assert.equal(result.effectiveState, 'INCOMPLETE');
  assert.equal(checks.length, 0);
});

test('active member grant becomes effective only after authenticated principal checkDelegation succeeds', async () => {
  const { tenant, agent, checks } = fakeSessions(activePolicy(), { authorised: true, satisfied: [{ type: 'member_delegation' }], missing: [] });
  const result = await new DelegationService(tenant, agent).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'ACTIVE');
  assert.equal(result.effectiveState, 'ACTIVE');
  assert.deepEqual(result.satisfied, ['member_delegation']);
  assert.deepEqual(checks, [{ contract: 'z:tenant:privacy-guard', pii_did: 'did:t3n:tenant-test', functions: ['evaluate-action'], scopes: ['incident_id'] }]);
});

test('active member grant remains incomplete when T3N says principal is not authorised', async () => {
  const { tenant, agent } = fakeSessions(activePolicy(), { authorised: false, satisfied: ['member_delegation'], missing: ['required_authority'] });
  const result = await new DelegationService(tenant, agent).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'ACTIVE');
  assert.equal(result.effectiveState, 'INCOMPLETE');
  assert.deepEqual(result.missing, ['required_authority']);
});

test('active member grant fails closed when effective delegation check is unavailable or malformed', async () => {
  for (const verdict of [new Error('transport failed'), { satisfied: ['member_delegation'], missing: [] }] as Array<Verdict | Error>) {
    const { tenant, agent } = fakeSessions(activePolicy(), verdict);
    const result = await new DelegationService(tenant, agent).status('z:tenant:privacy-guard');
    assert.equal(result.memberState, 'ACTIVE');
    assert.equal(result.effectiveState, 'UNKNOWN');
  }
});

test('sanitizes malformed satisfied and missing metadata without exposing raw SDK objects', async () => {
  const { tenant, agent } = fakeSessions(activePolicy(), {
    authorised: true,
    satisfied: [{ type: 'member_delegation', raw: { secret: 'ignored' } }, { unexpected: 'ignored' }, 42],
    missing: [{ kind: 'scope' }, { token: 'ignored' }],
  });
  const result = await new DelegationService(tenant, agent).status('z:tenant:privacy-guard');
  assert.equal(result.effectiveState, 'ACTIVE');
  assert.deepEqual(result.satisfied, ['member_delegation']);
  assert.deepEqual(result.missing, ['scope']);
});

test('scheduled member grant is incomplete and never calls effective delegation check', async () => {
  const now = Math.floor(Date.now() / 1000);
  const { tenant, agent, checks } = fakeSessions({ grants: [{ grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', functions: ['evaluate-action'], scopes: ['incident_id'], window: { valid_from_secs: now + 300, valid_until_secs: now + 600 } }] });
  const result = await new DelegationService(tenant, agent).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'SCHEDULED');
  assert.equal(result.effectiveState, 'INCOMPLETE');
  assert.equal(checks.length, 0);
});

test('revoked member grant is incomplete and never calls effective delegation check', async () => {
  const now = Math.floor(Date.now() / 1000);
  const { tenant, agent, checks } = fakeSessions({ grants: [{ grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', functions: ['evaluate-action'], scopes: ['incident_id'], window: { valid_until_secs: now - 1 } }] });
  const result = await new DelegationService(tenant, agent).status('z:tenant:privacy-guard');
  assert.equal(result.memberState, 'REVOKED');
  assert.equal(result.effectiveState, 'INCOMPLETE');
  assert.equal(checks.length, 0);
});

test('reports UNKNOWN for unreadable or inverted matching grant windows', async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const window of [{ valid_from_secs: 'later' }, { valid_until_secs: 'later' }, { valid_from_secs: now + 600, valid_until_secs: now + 300 }]) {
    const { tenant, agent, checks } = fakeSessions({ grants: [{ grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', functions: ['evaluate-action'], scopes: ['incident_id'], window }] });
    const result = await new DelegationService(tenant, agent).status('z:tenant:privacy-guard');
    assert.equal(result.memberState, 'UNKNOWN');
    assert.equal(result.effectiveState, 'UNKNOWN');
    assert.equal(checks.length, 0);
  }
});

test('revoke returns NOT_GRANTED without writing a replacement policy when grant is absent', async () => {
  const { tenant, agent, updates } = fakeSessions({ grants: [] });
  const service = new DelegationService(tenant, agent);
  assert.equal(await service.revoke('z:tenant:privacy-guard'), 'NOT_GRANTED');
  assert.equal(updates.length, 0);
});

test('revoke expires only the matching grant and preserves its original restrictions', async () => {
  const { tenant, agent, updates } = fakeSessions({ grants: [{ grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', version_req: '0.3.0', functions: ['evaluate-action', 'execute-remediation', 'verify-remediation'], scopes: ['incident_id', 'credential_id', 'reason'], allowed_hosts: ['security.example', 'verification.example'], read_scopes: ['incident_id'] }] });
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
  await service.grant({ contractId: 'z:tenant:privacy-guard', versionReq: '0.3.0', functions: ['evaluate-action', 'verify-remediation'], scopes: ['incident_id'], allowedHosts: ['verification.example'] });
  assert.equal(updates.length, 1);
  assert.deepEqual(updates[0], { grantee: 'did:t3n:agent-test', contract_id: 'z:tenant:privacy-guard', version_req: '0.3.0', functions: ['evaluate-action', 'verify-remediation'], scopes: ['incident_id'], read_scopes: undefined, allowed_hosts: ['verification.example'], window: undefined });
});
