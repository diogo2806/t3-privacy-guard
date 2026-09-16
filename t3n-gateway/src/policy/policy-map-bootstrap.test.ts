import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { canonicalizeOperationalPolicy } from './policy-document.js';
import {
  activateOperationalPolicy,
  ensureImmutablePolicyVersion,
  readOptionalPolicyEntry,
} from './policy-map-bootstrap.js';

function target(version = '2026-09-16.1') {
  return canonicalizeOperationalPolicy({
    version,
    actions: {
      'revoke-credential': {
        purpose: 'incident-remediation',
        allowed_fields: ['incident_id', 'credential_id', 'reason'],
        allowed_hosts: ['api-privacy.iforce.com.br'],
        allowed_private_refs: [],
        requires_host: true,
        requires_human_authorization: true,
      },
      'notify-security': {
        purpose: 'incident-notification',
        allowed_fields: ['incident_id', 'severity', 'summary'],
        allowed_hosts: ['api-privacy.iforce.com.br'],
        allowed_private_refs: ['verified_email'],
        requires_host: true,
        requires_human_authorization: true,
      },
    },
  });
}

describe('policy map bootstrap', () => {
  it('treats an unavailable optional entry as absent before the first publish', async () => {
    const result = await readOptionalPolicyEntry(async () => {
      throw new Error('missing entry');
    }, 'current');

    assert.equal(result, null);
  });

  it('creates the immutable version entry when the optional version lookup is absent', async () => {
    const policy = target();
    const writes: Array<[string, string]> = [];

    await ensureImmutablePolicyVersion(
      policy,
      async () => { throw new Error('missing entry'); },
      async (key, value) => { writes.push([key, value]); },
    );

    assert.deepEqual(writes, [[`version:${policy.document.version}`, policy.canonicalJson]]);
  });

  it('fails when the immutable version entry cannot be written', async () => {
    const policy = target();

    await assert.rejects(
      ensureImmutablePolicyVersion(
        policy,
        async () => null,
        async () => { throw new Error('write failed'); },
      ),
      /write failed/,
    );
  });

  it('keeps the final current read-back strict', async () => {
    const policy = target();

    await assert.rejects(
      activateOperationalPolicy(
        policy,
        async () => { throw new Error('read-back unavailable'); },
        async () => undefined,
      ),
      /read-back unavailable/,
    );
  });

  it('fails closed when the final read-back does not match the target policy', async () => {
    const policy = target();
    const different = target('2026-09-16.2');

    await assert.rejects(
      activateOperationalPolicy(
        policy,
        async () => different.canonicalJson,
        async () => undefined,
      ),
      /read-back version\/hash mismatch/,
    );
  });

  it('accepts a publish only after exact write and read-back', async () => {
    const policy = target();
    let current: string | null = null;

    await activateOperationalPolicy(
      policy,
      async () => current,
      async (key, value) => {
        assert.equal(key, 'current');
        current = value;
      },
    );

    assert.equal(current, policy.canonicalJson);
  });
});
