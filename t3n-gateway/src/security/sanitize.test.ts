import assert from 'node:assert/strict';
import test from 'node:test';
import { sanitizeError, sanitizeText } from './sanitize.js';

const syntheticKey = `0x${'ab'.repeat(32)}`;
const syntheticOrgAgentKey = 't3n_key_agent01.secret_value_1234567890';

test('redacts exact secret and private-key shaped values', () => {
  const output = sanitizeText(`failed with ${syntheticKey}`, [syntheticKey]);
  assert.equal(output.includes(syntheticKey), false);
});

test('redacts organization-owned T3N agent credentials without requiring an explicit secret list', () => {
  const output = sanitizeText(`failed with ${syntheticOrgAgentKey}`);
  assert.equal(output.includes(syntheticOrgAgentKey), false);
  assert.equal(output.includes('secret_value_1234567890'), false);
  assert.match(output, /\[REDACTED_T3N_API_KEY\]/);
});

test('redacts malformed t3n_key-shaped tokens as a defensive fallback', () => {
  const malformed = 't3n_key_bad-with.secret_fragment';
  const output = sanitizeText(`failed with ${malformed}`);
  assert.equal(output.includes(malformed), false);
  assert.equal(output.includes('secret_fragment'), false);
});

test('classifies authentication failures without exposing secret', () => {
  const result = sanitizeError(new Error(`Unauthorized ${syntheticKey}`), [syntheticKey]);
  assert.equal(result.category, 'AUTHENTICATION');
  assert.equal(result.message.includes(syntheticKey), false);
});

test('classifies opaque-key authentication failures without exposing the credential', () => {
  const result = sanitizeError(new Error(`Unauthorized ${syntheticOrgAgentKey}`));
  assert.equal(result.category, 'AUTHENTICATION');
  assert.equal(result.message.includes(syntheticOrgAgentKey), false);
});

test('classifies an uninitialised organization policy as actionable configuration', () => {
  const result = sanitizeError(new Error('RPC Error: OrgPolicyNotInitialised: org policy is not initialised for this organisation'));
  assert.equal(result.category, 'CONFIGURATION');
});

test('classifies an unknown organization DID as actionable configuration', () => {
  const result = sanitizeError(new Error('RPC Error: OrganisationNotFound: organisation does not exist'));
  assert.equal(result.category, 'CONFIGURATION');
});
