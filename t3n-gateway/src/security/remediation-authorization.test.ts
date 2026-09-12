import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { RemediationAuthorizationVerifier, type RemediationBody } from './remediation-authorization.js';

const key = 'test-remediation-capability-key-1234567890';
const now = 1_800_000_000_000;
const body: RemediationBody = {
  incident_id: 'incident-1',
  action_id: 'action-1',
  decision_id: 'decision-1',
  request_id: 'request-1',
  action: 'revoke-credential',
  resource: 'credential:test',
  purpose: 'incident-remediation',
  fields: ['incident_id', 'credential_id', 'reason'],
};

function token(overrides: Record<string, unknown> = {}): string {
  const claims = {
    incidentId: body.incident_id,
    actionId: body.action_id,
    decisionId: body.decision_id,
    requestId: body.request_id,
    action: body.action,
    resource: body.resource,
    purpose: body.purpose,
    fieldsHash: createHash('sha256').update(JSON.stringify([...body.fields].sort())).digest('hex'),
    authorizedAt: now - 1_000,
    expiresAt: now + 60_000,
    nonce: 'nonce-1',
    ...overrides,
  };
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const signature = createHmac('sha256', key).update(payload, 'ascii').digest('base64url');
  return `${payload}.${signature}`;
}

test('valid capability is consumed and persisted across verifier instances', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const verifier = new RemediationAuthorizationVerifier(key, path, () => now);
  verifier.verifyAndConsume(token(), body);
  assert.match(readFileSync(path, 'utf8'), /nonce-1/);

  const afterRestart = new RemediationAuthorizationVerifier(key, path, () => now);
  assert.throws(() => afterRestart.verifyAndConsume(token(), body), /CAPABILITY_REPLAY/);
});

test('tampered body is rejected before execution', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const verifier = new RemediationAuthorizationVerifier(key, path, () => now);
  assert.throws(() => verifier.verifyAndConsume(token(), { ...body, purpose: 'analytics' }), /CAPABILITY_BODY_MISMATCH/);
});

test('expired capability is rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const verifier = new RemediationAuthorizationVerifier(key, path, () => now);
  assert.throws(() => verifier.verifyAndConsume(token({ expiresAt: now - 1 }), body), /CAPABILITY_EXPIRED/);
});

test('signature tampering is rejected', () => {
  const path = join(mkdtempSync(join(tmpdir(), 't3pg-cap-')), 'nonces.json');
  const verifier = new RemediationAuthorizationVerifier(key, path, () => now);
  const valid = token();
  assert.throws(() => verifier.verifyAndConsume(`${valid.slice(0, -1)}A`, body), /CAPABILITY_INVALID/);
});
