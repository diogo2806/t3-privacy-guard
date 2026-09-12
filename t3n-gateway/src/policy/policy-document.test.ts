import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalizeOperationalPolicy } from './policy-document.js';

const baseline = {
  version: '2026-09-12.1',
  actions: {
    'revoke-credential': {
      purpose: 'incident-remediation',
      allowed_fields: ['reason', 'incident_id', 'credential_id'],
      allowed_hosts: ['security-api.internal', 'postman-echo.com'],
      allowed_private_refs: [],
      requires_host: true,
      requires_human_authorization: true,
    },
  },
};

test('canonical hash is stable regardless of input list order', () => {
  const first = canonicalizeOperationalPolicy(baseline);
  const second = canonicalizeOperationalPolicy({
    version: baseline.version,
    actions: {
      'revoke-credential': {
        ...baseline.actions['revoke-credential'],
        allowed_fields: ['credential_id', 'reason', 'incident_id'],
        allowed_hosts: ['postman-echo.com', 'security-api.internal'],
      },
    },
  });
  assert.equal(first.hash, second.hash);
  assert.equal(first.canonicalJson, second.canonicalJson);
});

test('changing an operational rule changes the hash', () => {
  const first = canonicalizeOperationalPolicy(baseline);
  const changed = canonicalizeOperationalPolicy({
    ...baseline,
    actions: {
      'revoke-credential': {
        ...baseline.actions['revoke-credential'],
        allowed_hosts: ['security-api.internal'],
      },
    },
  });
  assert.notEqual(first.hash, changed.hash);
});

test('policy cannot externalize contract-forbidden secrets or unknown private refs', () => {
  assert.throws(() => canonicalizeOperationalPolicy({
    ...baseline,
    actions: { 'revoke-credential': { ...baseline.actions['revoke-credential'], allowed_fields: ['api_key'] } },
  }), /forbidden secret/i);
  assert.throws(() => canonicalizeOperationalPolicy({
    ...baseline,
    actions: { 'revoke-credential': { ...baseline.actions['revoke-credential'], allowed_private_refs: ['arbitrary_secret'] } },
  }), /unknown private reference/i);
});

test('duplicate values after normalization are rejected', () => {
  assert.throws(() => canonicalizeOperationalPolicy({
    ...baseline,
    actions: { 'revoke-credential': { ...baseline.actions['revoke-credential'], allowed_fields: ['reason', ' REASON '] } },
  }), /duplicate normalized/i);
});
