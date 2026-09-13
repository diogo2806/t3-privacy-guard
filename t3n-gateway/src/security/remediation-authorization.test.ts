import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { RemediationAuthorizationVerifier, type RemediationBody } from './remediation-authorization.js';

const key = 'test-remediation-capability-key-1234567890';
const now = 1_800_000_000_000;
const policyVersion = '2026-09-12.1';
const policyHash = 'a'.repeat(64);
const body: RemediationBody = {
  incident_id: 'incident-1', action_id: 'action-1', decision_id: 'decision-1', request_id: 'request-1',
  action: 'notify-security', resource: 'incident:test', purpose: 'incident-notification',
  fields: ['incident_id', 'severity', 'summary'], private_refs: ['verified_email'],
  policy_version: policyVersion, policy_hash: policyHash,
};

function listHash(values: string[]): string {
  return createHash('sha256').update(JSON.stringify([...values].map((value) => value.trim()).sort())).digest('hex');
}

function token(overrides: Record<string, unknown> = {}): string {
  const claims = {
    incidentId: body.incident_id, actionId: body.action_id, decisionId: body.decision_id, requestId: body.request_id,
    action: body.action, resource: body.resource, purpose: body.purpose,
    fieldsHash: listHash(body.fields), privateRefsHash: listHash(body.private_refs),
    policyVersion: body.policy_version, policyHash: body.policy_hash,
    authorizedAt: now - 1_000, expiresAt: now + 60_000, nonce: 'nonce-1', ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = createHmac('sha256', key).update(payload, 'ascii').digest('base64url');
  return `${payload}.${signature}`;
}

test('valid capability is consumed and persisted across verifier instances', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  new RemediationAuthorizationVerifier(key, path, () => now).verifyAndConsume(token(), body);
  assert.match(readFileSync(path, 'utf8'), /nonce-1/);
  assert.throws(() => new RemediationAuthorizationVerifier(key, path, () => now).verifyAndConsume(token(), body), /CAPABILITY_REPLAY/);
});

test('tampered purpose private reference or policy provenance is rejected before execution', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const verifier = new RemediationAuthorizationVerifier(key, path, () => now);
  assert.throws(() => verifier.verifyAndConsume(token(), { ...body, purpose: 'analytics' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-2' }), { ...body, private_refs: [] }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-3' }), { ...body, policy_version: '2026-09-11.1' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-4' }), { ...body, policy_hash: 'b'.repeat(64) }), /CAPABILITY_BODY_MISMATCH/);
});

test('expired capability is rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => new RemediationAuthorizationVerifier(key, path, () => now).verifyAndConsume(token({ expiresAt: now - 1 }), body), /CAPABILITY_EXPIRED/);
});

test('signature tampering is rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const valid = token();
  assert.throws(() => new RemediationAuthorizationVerifier(key, path, () => now).verifyAndConsume(`${valid.slice(0, -1)}A`, body), /CAPABILITY_INVALID/);
});
