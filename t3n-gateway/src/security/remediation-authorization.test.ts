import assert from 'node:assert/strict';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { canonicalNormalPayload, canonicalizeApprovedHost, normalPayloadHash, RemediationAuthorizationVerifier, type RemediationBody } from './remediation-authorization.js';

const privateKeyPkcs8 = 'MC4CAQAwBQYDK2VwBCIEIAv4OIfbF/R/i9uL6wgRalq2gperSKNx+Ig9BuS9L4qS';
const publicKeySpki = 'MCowBQYDK2VwAyEAW3EwSatHmT/ZSgrqu/G3ecXJrTviA5SjAoCwIfwau6A=';
const keyId = 'primary';
const privateKey = createPrivateKey({ key: Buffer.from(privateKeyPkcs8, 'base64'), format: 'der', type: 'pkcs8' });
const now = 1_800_000_000_000;
const policyVersion = '2026-09-12.1';
const policyHash = 'a'.repeat(64);
const executorDid = 'did:t3n:protected-executor-test';
const operatorPrincipalHash = 'b'.repeat(64);
const authorizedAt = now - 2_000;
const body: RemediationBody = {
  incident_id: 'incident-1', action_id: 'action-1', decision_id: 'decision-1', request_id: 'request-1',
  action: 'revoke-credential', resource: 'credential:test', purpose: 'incident-remediation', approved_host: 'security-a.example',
  fields: ['incident_id', 'credential_id', 'reason'],
  normal_payload: { incident_id: 'inc-demo-001', credential_id: 'cred-demo-001', reason: 'suspected compromise' },
  private_refs: [], policy_version: policyVersion, policy_hash: policyHash, executor_did: executorDid,
  operator_principal_hash: operatorPrincipalHash, authorization_recorded_at: authorizedAt,
};

function verifier(path: string) {
  return new RemediationAuthorizationVerifier(publicKeySpki, keyId, path, () => now);
}

function listHash(values: string[]): string {
  return createHash('sha256').update(JSON.stringify([...values].map((value) => value.trim()).sort())).digest('hex');
}

function token(overrides: Record<string, unknown> = {}): string {
  const claims = {
    keyId,
    incidentId: body.incident_id, actionId: body.action_id, decisionId: body.decision_id, requestId: body.request_id,
    action: body.action, resource: body.resource, purpose: body.purpose, approvedHost: body.approved_host,
    fieldsHash: listHash(body.fields), normalPayloadHash: normalPayloadHash(body.normal_payload), privateRefsHash: listHash(body.private_refs),
    policyVersion: body.policy_version, policyHash: body.policy_hash, executorDid: body.executor_did,
    operatorPrincipalHash: body.operator_principal_hash, authorizedAt: body.authorization_recorded_at,
    issuedAt: now - 1_000, expiresAt: now + 60_000, nonce: 'nonce-00000001', ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signingInput = `v2.${payload}`;
  const signature = sign(null, Buffer.from(signingInput, 'ascii'), privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

test('normal payload canonicalization matches the Java cross-runtime vector', () => {
  assert.equal(
    canonicalNormalPayload(body.normal_payload),
    '13:credential_id=13:cred-demo-001\n11:incident_id=12:inc-demo-001\n6:reason=20:suspected compromise\n',
  );
  assert.equal(normalPayloadHash(body.normal_payload), '39ba6c4944b8e22ae8bb5bb1ebc7d98839593f17d51acd5d5aff31c81ebaa8ae');
});

test('valid v2 capability carries key version and human provenance and consumes only the nonce hash', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const claims = verifier(path).verifyAndConsume(token(), body);
  assert.equal(claims.keyId, keyId);
  assert.equal(claims.operatorPrincipalHash, operatorPrincipalHash);
  assert.equal(claims.authorizedAt, authorizedAt);
  const stored = readFileSync(path, 'utf8');
  assert.doesNotMatch(stored, /nonce-00000001/);
  assert.match(stored, /nonceHash/);
  assert.throws(() => verifier(path).verifyAndConsume(token(), body), /CAPABILITY_REPLAY/);
});

test('wrong or unsafe key id fails closed', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => verifier(path).verifyAndConsume(token({ keyId: 'old-key' }), body), /CAPABILITY_KEY_MISMATCH/);
  assert.throws(() => verifier(path).verifyAndConsume(token({ keyId: '..\/bad' }), body), /CAPABILITY_KEY_MISMATCH/);
});

test('tampered purpose destination payload private reference policy executor or human provenance is rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const current = verifier(path);
  assert.throws(() => current.verifyAndConsume(token(), { ...body, purpose: 'analytics' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-host-0001' }), { ...body, approved_host: 'security-b.example' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-value-0001' }), { ...body, normal_payload: { ...body.normal_payload, reason: 'changed after approval' } }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-private-01' }), { ...body, private_refs: ['verified_email'] }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-policy-v1' }), { ...body, policy_version: '2026-09-11.1' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-policy-h1' }), { ...body, policy_hash: 'c'.repeat(64) }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-executor1' }), { ...body, executor_did: 'did:t3n:other-executor' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-human-h1' }), { ...body, operator_principal_hash: 'd'.repeat(64) }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-human-t1' }), { ...body, authorization_recorded_at: authorizedAt - 1 }), /CAPABILITY_BODY_MISMATCH/);
});

test('invalid human provenance or time ordering fails closed', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const current = verifier(path);
  assert.throws(() => current.verifyAndConsume(token({ operatorPrincipalHash: 'invalid' }), body), /CAPABILITY_INVALID/);
  assert.throws(() => current.verifyAndConsume(token({ authorizedAt: now + 1_000, issuedAt: now }), body), /CAPABILITY_INVALID/);
  assert.throws(() => current.verifyAndConsume(token(), { ...body, operator_principal_hash: 'invalid' }), /CAPABILITY_INVALID/);
});

test('approved destination must be an exact canonical hostname', () => {
  assert.equal(canonicalizeApprovedHost('security-a.example'), 'security-a.example');
  for (const invalid of ['Security-A.Example', 'https://security-a.example/remediate', 'security-a.example:443', 'user@security-a.example', '-bad.example']) {
    assert.throws(() => canonicalizeApprovedHost(invalid), /CAPABILITY_INVALID/);
  }
});

test('expired future legacy or signature-tampered capability is rejected with no downgrade', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const current = verifier(path);
  assert.throws(() => current.verifyAndConsume(token({ expiresAt: now - 1 }), body), /CAPABILITY_EXPIRED/);
  assert.throws(() => current.verifyAndConsume(token({ issuedAt: now + 10_000, expiresAt: now + 20_000 }), body), /CAPABILITY_INVALID/);
  assert.throws(() => current.verifyAndConsume('legacy.payload', body), /CAPABILITY_INVALID/);
  const valid = token({ nonce: 'nonce-signature-1' });
  assert.throws(() => current.verifyAndConsume(`${valid.slice(0, -1)}A`, body), /CAPABILITY_INVALID/);
});
