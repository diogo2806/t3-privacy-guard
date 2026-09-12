import assert from 'node:assert/strict';
import test from 'node:test';
import { validateAgentProposal } from './proposal-schema.js';

test('accepts only the minimum structured proposal surface', () => {
  const proposal = validateAgentProposal({
    action: 'revoke-credential',
    resource: 'credential:test',
    purpose: 'incident-remediation',
    host: 'postman-echo.com',
    fields: ['incident_id', 'credential_id', 'reason'],
  });
  assert.equal(proposal.action, 'revoke-credential');
  assert.deepEqual(proposal.fields, ['incident_id', 'credential_id', 'reason']);
});

test('rejects model attempts to decide authorization or inject identity', () => {
  for (const extra of [
    { decision: 'ALLOW' },
    { override: true },
    { approved: true },
    { agent_did: 'did:t3n:attacker' },
    { pii_did: 'did:t3n:victim' },
    { api_key: 'secret' },
  ]) {
    assert.throws(() => validateAgentProposal({
      action: 'revoke-credential',
      resource: 'credential:test',
      purpose: 'incident-remediation',
      host: 'postman-echo.com',
      fields: ['incident_id'],
      ...extra,
    }), /AGENT_PROPOSAL_FORBIDDEN_FIELD/);
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
