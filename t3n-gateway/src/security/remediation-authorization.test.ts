import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { canonicalizeApprovedHost, RemediationAuthorizationVerifier, type RemediationBody } from './remediation-authorization.js';

const keyPair = generateKeyPairSync('ed25519');
const publicKeyDer = keyPair.publicKey.export({ format: 'der', type: 'spki' });
const publicKeyHex = publicKeyDer.subarray(publicKeyDer.length - 32).toString('hex');
const keyId = 'test-v2';
const now = 1_800_000_000;
const policyVersion = '2026-09-12.1';
const policyHash = 'a'.repeat(64);
const executorDid = 'did:t3n:protected-executor-test';
const body: RemediationBody = {
  incident_id: 'incident-1', action_id: 'action-1', decision_id: 'decision-1', request_id: 'request-1',
  action: 'revoke-credential', resource: 'credential:test', purpose: 'incident-remediation', approved_host: 'security-a.example',
  fields: ['incident_id', 'severity', 'summary'], private_refs: ['verified_email'],
  policy_version: policyVersion, policy_hash: policyHash, executor_did: executorDid,
};

function listHash(values: string[]): string {
  return createHash('sha256').update(JSON.stringify([...values].map((value) => value.trim()).sort())).digest('hex');
}

function token(overrides: Record<string, unknown> = {}): string {
  const claims = {
    keyId,
    incidentId: body.incident_id, actionId: body.action_id, decisionId: body.decision_id, requestId: body.request_id,
    action: body.action, resource: body.resource, purpose: body.purpose, approvedHost: body.approved_host,
    fieldsHash: listHash(body.fields), privateRefsHash: listHash(body.private_refs),
    policyVersion: body.policy_version, policyHash: body.policy_hash, executorDid: body.executor_did,
    issuedAt: now - 1, expiresAt: now + 60, nonce: 'nonce-1', ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signingInput = `v2.${payload}`;
  const signature = sign(null, Buffer.from(signingInput, 'ascii'), keyPair.privateKey).toString('hex');
  return `${signingInput}.${signature}`;
}

function verifier(path: string): RemediationAuthorizationVerifier {
  return new RemediationAuthorizationVerifier(publicKeyHex, keyId, path, () => now);
}

test('valid v2 capability is consumed and persisted across verifier instances', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  verifier(path).verifyAndConsume(token(), body);
  assert.match(readFileSync(path, 'utf8'), /nonce-1/);
  assert.throws(() => verifier(path).verifyAndConsume(token(), body), /CAPABILITY_REPLAY/);
});

test('tampered purpose destination private reference policy provenance or executor is rejected before execution', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const current = verifier(path);
  assert.throws(() => current.verifyAndConsume(token(), { ...body, purpose: 'analytics' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-host' }), { ...body, approved_host: 'security-b.example' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-2' }), { ...body, private_refs: [] }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-3' }), { ...body, policy_version: '2026-09-11.1' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-4' }), { ...body, policy_hash: 'b'.repeat(64) }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-5' }), { ...body, executor_did: 'did:t3n:other-executor' }), /CAPABILITY_BODY_MISMATCH/);
  assert.throws(() => current.verifyAndConsume(token({ nonce: 'nonce-6' }), { ...body, decision_id: 'other-decision' }), /CAPABILITY_BODY_MISMATCH/);
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

test('expired and overlong capabilities are rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  assert.throws(() => verifier(path).verifyAndConsume(token({ issuedAt: now - 61, expiresAt: now }), body), /CAPABILITY_EXPIRED/);
  assert.throws(() => verifier(path).verifyAndConsume(token({ issuedAt: now - 1, expiresAt: now + 301 }), body), /CAPABILITY_INVALID/);
});

test('signature tampering, wrong key id and legacy proof formats are rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const valid = token();
  const last = valid.at(-1) === '0' ? '1' : '0';
  assert.throws(() => verifier(path).verifyAndConsume(`${valid.slice(0, -1)}${last}`, body), /CAPABILITY_INVALID/);
  assert.throws(() => verifier(path).verifyAndConsume(token({ keyId: 'rotated-v2' }), body), /CAPABILITY_INVALID/);
  assert.throws(() => verifier(path).verifyAndConsume('payload.signature', body), /CAPABILITY_INVALID/);
  assert.throws(() => verifier(path).verifyAndConsume('v1.payload.signature', body), /CAPABILITY_INVALID/);
});
