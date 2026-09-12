import assert from 'node:assert/strict';
import test from 'node:test';
import { validateAgentProposal } from './proposal-schema.js';

function validProposal() {
  return {
    action: 'revoke-credential',
    resource: 'credential:test',
    purpose: 'incident-remediation',
    host: 'postman-echo.com',
    fields: ['incident_id', 'credential_id', 'reason'],
    private_refs: [] as string[],
  };
}

function seeded(seed = 0x53a9f17d) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

test('accepts only the minimum structured proposal surface', () => {
  const proposal = validateAgentProposal(validProposal());
  assert.equal(proposal.action, 'revoke-credential');
  assert.deepEqual(proposal.fields, ['incident_id', 'credential_id', 'reason']);
});

test('rejects model attempts to decide authorization or inject identity', () => {
  for (const extra of [
    { decision: 'ALLOW' },
    { allow: true },
    { override: true },
    { approved: true },
    { agent_did: 'did:t3n:attacker' },
    { pii_did: 'did:t3n:victim' },
    { credential: 'synthetic' },
    { secret: 'synthetic' },
    { apiKey: 'synthetic' },
    { api_key: 'synthetic' },
  ]) {
    assert.throws(() => validateAgentProposal({ ...validProposal(), ...extra }), /AGENT_PROPOSAL_FORBIDDEN_FIELD/);
  }
});

test('rejects unknown keys and oversized field sets', () => {
  assert.throws(() => validateAgentProposal({
    action: 'revoke-credential', resource: 'credential:test', purpose: 'incident-remediation', fields: [], unexpected: 'x',
  }), /AGENT_PROPOSAL_FORBIDDEN_FIELD/);
  assert.throws(() => validateAgentProposal({
    action: 'revoke-credential', resource: 'credential:test', purpose: 'incident-remediation', fields: Array.from({ length: 21 }, (_, i) => `f${i}`),
  }), /AGENT_PROPOSAL_INVALID_FIELDS/);
});

test('property: generated authority fields are always rejected with reproducible seed 0x53a9f17d', () => {
  const random = seeded();
  const forbidden = ['decision', 'allow', 'override', 'approved', 'agent_did', 'pii_did', 'credential', 'secret', 'apiKey', 'api_key'];
  for (let index = 0; index < 1_000; index += 1) {
    const key = forbidden[random() % forbidden.length];
    const value = `synthetic-${random().toString(16)}`;
    assert.throws(
      () => validateAgentProposal({ ...validProposal(), [key]: value }),
      /AGENT_PROPOSAL_FORBIDDEN_FIELD/,
      `seed=0x53a9f17d case=${index} key=${key}`,
    );
  }
});

test('property: private references are a closed enum and literal placeholders never cross the schema', () => {
  const random = seeded(0x91c4e2b7);
  for (let index = 0; index < 1_000; index += 1) {
    const candidate = index % 3 === 0
      ? `unknown_${random().toString(36)}`
      : index % 3 === 1
        ? `{{profile.${random().toString(36)}}}`
        : `profile.${random().toString(36)}`;
    assert.throws(
      () => validateAgentProposal({ ...validProposal(), private_refs: [candidate] }),
      /AGENT_PROPOSAL_(PRIVATE_REFERENCE_UNKNOWN|RAW_PLACEHOLDER_FORBIDDEN)/,
      `seed=0x91c4e2b7 case=${index}`,
    );
  }
  assert.deepEqual(validateAgentProposal({ ...validProposal(), private_refs: ['verified_email'] }).private_refs, ['verified_email']);
});

test('property: cardinality and string limits fail closed', () => {
  const random = seeded(0x4a778e31);
  for (let index = 0; index < 256; index += 1) {
    const count = 21 + (random() % 40);
    assert.throws(
      () => validateAgentProposal({ ...validProposal(), fields: Array.from({ length: count }, (_, i) => `field_${i}`) }),
      /AGENT_PROPOSAL_INVALID_FIELDS/,
      `seed=0x4a778e31 case=${index}`,
    );
    assert.throws(
      () => validateAgentProposal({ ...validProposal(), action: 'a'.repeat(81 + (random() % 100)) }),
      /AGENT_PROPOSAL_INVALID_ACTION/,
      `seed=0x4a778e31 action case=${index}`,
    );
  }
});
