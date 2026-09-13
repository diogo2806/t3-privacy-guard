import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { canonicalNormalPayload, canonicalizeApprovedHost, normalPayloadHash, RemediationAuthorizationVerifier, type RemediationBody } from './remediation-authorization.js';

const key = 'test-remediation-capability-key-1234567890';
const now = 1_800_000_000_000;
const policyVersion = '2026-09-12.1';
const policyHash = 'a'.repeat(64);
const executorDid = 'did:t3n:protected-executor-test';
const body: RemediationBody = {
  incident_id: 'incident-1', action_id: 'action-1', decision_id: 'decision-1', request_id: 'request-1',
  action: 'revoke-credential', resource: 'credential:test', purpose: 'incident-remediation', approved_host: 'security-a.example',
  fields: ['incident_id', 'credential_id', 'reason'],
  normal_payload: { incident_id: 'inc-demo-001', credential_id: 'cred-demo-001', reason: 'suspected compromise' },
  private_refs: [], policy_version: policyVersion, policy_hash: policyHash, executor_did: executorDid,
};

function listHash(values: string[]): string {
  return createHash('sha256').update(JSON.stringify([...values].map((value) => value.trim()).sort())).digest('hex');
}

function token(overrides: Record<string, unknown> = {}): string {
  const claims = {
    incidentId: body.incident_id, actionId: body.action_id, decisionId: body.decision_id, requestId: body.request_id,
    action: body.action, resource: body.resource, purpose: body.purpose, approvedHost: body.approved_host,
    fieldsHash: listHash(body.fields), normalPayloadHash: normalPayloadHash(body.normal_payload), privateRefsHash: listHash(body.private_refs),
    policyVersion: body.policy_version, policyHash: body.policy_hash, executorDid: body.executor_did,
    authorizedAt: now - 1_000, expiresAt: now + 60_000, nonce: 'nonce-1', ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = createHmac('sha256', key).update(payload, 'ascii').digest('base64url');
  return `${payload}.${signature}`;
}

test('normal payload canonicalization matches the Java cross-runtime vector', () => {
  assert.equal(
    canonicalNormalPayload(body.normal_payload),
    '13:credential_id=13:cred-demo-001\n11:incident_id=12:inc-demo-001\n6:reason=20:suspected compromise\n',
  );
  assert.equal(normalPayloadHash(body.normal_payload), '39ba6c4944b8e22ae8bb5bb1ebc7d98839593f17d51acd5d5aff31c81ebaa8ae');
});

test('valid capability is consumed and persisted across verifier instances', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  new RemediationAuthorizationVerifier(key, path, () => now).verifyAndConsume(token(), body);
  assert.match(readFileSync(path, 'utf8'), /nonce-1/);
  assert.throws(() => new RemediationAuthorizationVerifier(key, path, () => now).verifyAndConsume(token(), body), /CAPABILITY_REPLAY/);
});

test('tampered purpose destination payload private reference policy provenance or executor is rejected before execution', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const verifier = new RemediationAuthorizationVerifier(key, path, () => now);
  assert.throws(() => verifier.verifyAndConsume(token(), { ...body, purpose: 'analytics' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-host' }), { ...body, approved_host: 'security-b.example' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-value' }), { ...body, normal_payload: { ...body.normal_payload, reason: 'changed after approval' } }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-key' }), { ...body, normal_payload: { ...body.normal_payload, employee_department: 'finance' } }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-2' }), { ...body, private_refs: ['verified_email'] }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-3' }), { ...body, policy_version: '2026-09-11.1' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-4' }), { ...body, policy_hash: 'b'.repeat(64) }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => verifier.verifyAndConsume(token({ nonce: 'nonce-5' }), { ...body, executor_did: 'did:t3n:other-executor' }), /CAPABILITY_BODY_MISMATCH/);
});

test('approved destination must be an exact canonical hostname', () => {
  assert.equal(canonicalizeApprovedHost('security-a.example'), 'security-a.example');
  for (const invalid of ['Security-A.Example', 'https://security-a.example/remediate', 'security-a.example:443', 'user@security-a.example', '-bad.example']) {
    assert.throws(() => canonicalizeApprovedHost(invalid), /CAPABILITY_INVALID/);
  }
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => new RemediationAuthorizationVerifier(key, path, () => now).verifyAndConsume(token(), { ...body, approved_host: 'https://security-a.example' }), /CAPABILITY_INVALID/);
});

test('capability without canonical executor DID is rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => new RemediationAuthorizationVerifier(key, path, () => now).verifyAndConsume(token({ executorDid: 'executor-local' }), body), /CAPABILITY_INVALID/);
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
