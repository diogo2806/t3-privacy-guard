import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as signData } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { canonicalNormalPayload, canonicalizeApprovedHost, normalPayloadHash, RemediationAuthorizationVerifier, type RemediationBody } from './remediation-authorization.js';

const keyPair = generateKeyPairSync('ed25519');
const publicSpki = keyPair.publicKey.export({ format: 'der', type: 'spki' });
const publicKey = publicSpki.subarray(publicSpki.length - 32).toString('base64url');
const keyId = 'v1';
const now = 1_800_000_000_000;
const policyVersion = '2026-09-12.1';
const policyHash = 'a'.repeat(64);
const executorDid = 'did:t3n:protected-executor-test';
const operatorPrincipalHash = createHash('sha256').update('ops-reviewer', 'utf8').digest('hex');
const authorizationRecordedAt = now - 2_000;
const body: RemediationBody = {
  incident_id: 'incident-1', action_id: 'action-1', decision_id: 'decision-1', request_id: 'request-1',
  action: 'revoke-credential', resource: 'credential:test', purpose: 'incident-remediation', approved_host: 'security-a.example',
  fields: ['incident_id', 'credential_id', 'reason'],
  normal_payload: { incident_id: 'inc-demo-001', credential_id: 'cred-demo-001', reason: 'suspected compromise' },
  private_refs: [], policy_version: policyVersion, policy_hash: policyHash, executor_did: executorDid,
  operator_principal_hash: operatorPrincipalHash, authorization_recorded_at: authorizationRecordedAt,
};

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
    issuedAt: now - 1_000, expiresAt: now + 60_000, nonce: 'nonce-1', ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = signData(null, Buffer.from(payload, 'ascii'), keyPair.privateKey).toString('base64url');
  return `v2.${payload}.${signature}`;
}

function verifier(path: string): RemediationAuthorizationVerifier {
  return new RemediationAuthorizationVerifier(publicKey, keyId, path, () => now);
}

test('normal payload canonicalization matches the Java cross-runtime vector', () => {
  assert.equal(
    canonicalNormalPayload(body.normal_payload),
    '13:credential_id=13:cred-demo-001\n11:incident_id=12:inc-demo-001\n6:reason=20:suspected compromise\n',
  );
  assert.equal(normalPayloadHash(body.normal_payload), '39ba6c4944b8e22ae8bb5bb1ebc7d98839593f17d51acd5d5aff31c81ebaa8ae');
});

test('valid asymmetric capability is consumed and persisted across verifier instances', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  verifier(path).verifyAndConsume(token(), body);
  assert.match(readFileSync(path, 'utf8'), /nonce-1/);
  assert.throws(() => verifier(path).verifyAndConsume(token(), body), /CAPABILITY_REPLAY/);
});

test('tampered purpose destination payload private reference policy provenance executor or human approval is rejected before execution', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const instance = verifier(path);
  assert.throws(() => instance.verifyAndConsume(token(), { ...body, purpose: 'analytics' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => instance.verifyAndConsume(token({ nonce: 'nonce-host' }), { ...body, approved_host: 'security-b.example' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => instance.verifyAndConsume(token({ nonce: 'nonce-value' }), { ...body, normal_payload: { ...body.normal_payload, reason: 'changed after approval' } }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => instance.verifyAndConsume(token({ nonce: 'nonce-key' }), { ...body, normal_payload: { ...body.normal_payload, employee_department: 'finance' } }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => instance.verifyAndConsume(token({ nonce: 'nonce-2' }), { ...body, private_refs: ['verified_email'] }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => instance.verifyAndConsume(token({ nonce: 'nonce-3' }), { ...body, policy_version: '2026-09-11.1' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => instance.verifyAndConsume(token({ nonce: 'nonce-4' }), { ...body, policy_hash: 'b'.repeat(64) }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => instance.verifyAndConsume(token({ nonce: 'nonce-5' }), { ...body, executor_did: 'did:t3n:other-executor' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => instance.verifyAndConsume(token({ nonce: 'nonce-human-hash' }), { ...body, operator_principal_hash: 'b'.repeat(64) }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => instance.verifyAndConsume(token({ nonce: 'nonce-human-time' }), { ...body, authorization_recorded_at: authorizationRecordedAt - 1 }), /CAPABILITY_BODY_MISMATCH/);
});

test('capability requires a valid persisted human authorization binding', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const instance = verifier(path);
  assert.throws(() => instance.verifyAndConsume(token({ operatorPrincipalHash: undefined }), body), /CAPABILITY_INVALID/);
  assert.throws(() => instance.verifyAndConsume(token({ operatorPrincipalHash: 'not-a-hash', nonce: 'bad-hash' }), body), /CAPABILITY_INVALID/);
  assert.throws(() => instance.verifyAndConsume(token({ authorizedAt: now, issuedAt: now - 1_000, nonce: 'bad-time' }), body), /CAPABILITY_INVALID/);
  assert.throws(() => instance.verifyAndConsume(token({ issuedAt: now + 6_000, expiresAt: now + 60_000, nonce: 'future-issue' }), body), /CAPABILITY_INVALID/);
});

test('approved destination must be an exact canonical hostname', () => {
  assert.equal(canonicalizeApprovedHost('security-a.example'), 'security-a.example');
  for (const invalid of ['Security-A.Example', 'https://security-a.example/remediate', 'security-a.example:443', 'user@security-a.example', '-bad.example']) {
    assert.throws(() => canonicalizeApprovedHost(invalid), /CAPABILITY_INVALID/);
  }
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => verifier(path).verifyAndConsume(token(), { ...body, approved_host: 'https://security-a.example' }), /CAPABILITY_INVALID/);
});

test('capability without canonical executor DID is rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => verifier(path).verifyAndConsume(token({ executorDid: 'executor-local' }), body), /CAPABILITY_INVALID/);
});

test('expired capability is rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => verifier(path).verifyAndConsume(token({ expiresAt: now - 1 }), body), /CAPABILITY_EXPIRED/);
});

test('wrong key id legacy version and signature tampering are rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => verifier(path).verifyAndConsume(token({ keyId: 'v2' }), body), /CAPABILITY_KEY_MISMATCH/);
  assert.throws(() => verifier(path).verifyAndConsume(token().replace(/^v2\./, 'v1.'), body), /CAPABILITY_INVALID/);
  const valid = token();
  assert.throws(() => verifier(path).verifyAndConsume(`${valid.slice(0, -1)}A`, body), /CAPABILITY_INVALID/);
});

test('malformed public key configuration fails closed', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => new RemediationAuthorizationVerifier('short', keyId, path, () => now), /CAPABILITY_PUBLIC_KEY_INVALID/);
});