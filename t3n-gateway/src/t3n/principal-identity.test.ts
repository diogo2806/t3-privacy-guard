import assert from 'node:assert/strict';
import test from 'node:test';
import {
  assertDistinctPrincipalDids,
  PrincipalIdentityConflictError,
  PrincipalIdentityGuard,
} from './principal-identity.js';

const tenantDid = 'did:t3n:tenant1';
const proposalDid = 'did:t3n:proposal1';
const executorDid = 'did:t3n:executor1';

test('accepts three distinct authenticated principal DIDs', () => {
  assert.doesNotThrow(() => assertDistinctPrincipalDids({
    tenantDid,
    proposalAgentDid: proposalDid,
    protectedExecutorDid: executorDid,
  }));
});

test('rejects every pairwise DID reuse', () => {
  const conflicts = [
    { tenantDid, proposalAgentDid: tenantDid, protectedExecutorDid: executorDid },
    { tenantDid, proposalAgentDid: proposalDid, protectedExecutorDid: tenantDid },
    { tenantDid, proposalAgentDid: proposalDid, protectedExecutorDid: proposalDid },
  ];
  for (const snapshot of conflicts) {
    assert.throws(() => assertDistinctPrincipalDids(snapshot), PrincipalIdentityConflictError);
  }
});

test('validates only authenticated identities when an optional principal is absent', () => {
  assert.doesNotThrow(() => assertDistinctPrincipalDids({
    tenantDid,
    proposalAgentDid: proposalDid,
    protectedExecutorDid: null,
  }));
  assert.throws(() => assertDistinctPrincipalDids({
    tenantDid,
    proposalAgentDid: tenantDid,
    protectedExecutorDid: null,
  }), PrincipalIdentityConflictError);
});

test('keeps a detected conflict fail-closed in readiness until the conflicting DID changes or clears', () => {
  const guard = new PrincipalIdentityGuard();
  guard.recordAuthenticated('tenant', tenantDid);
  assert.throws(() => guard.recordAuthenticated('proposal-agent', tenantDid), PrincipalIdentityConflictError);

  const conflicted = guard.protectStatus({ ready: true, lastError: null });
  assert.equal(conflicted.ready, false);
  assert.equal(conflicted.lastError?.category, 'AUTHENTICATION');
  assert.match(conflicted.lastError?.message ?? '', /distinct DIDs/);

  guard.recordAuthenticated('proposal-agent', proposalDid);
  assert.deepEqual(guard.protectStatus({ ready: true, lastError: null }), { ready: true, lastError: null });

  guard.clear('proposal-agent');
  assert.doesNotThrow(() => guard.assertDistinct());
});
