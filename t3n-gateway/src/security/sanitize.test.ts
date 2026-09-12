import assert from 'node:assert/strict';
import test from 'node:test';
import { sanitizeError, sanitizeText } from './sanitize.js';

const syntheticKey = `0x${'ab'.repeat(32)}`;

test('redacts exact secret and private-key shaped values', () => {
  const output = sanitizeText(`failed with ${syntheticKey}`, [syntheticKey]);
  assert.equal(output.includes(syntheticKey), false);
});

test('classifies authentication failures without exposing secret', () => {
  const result = sanitizeError(new Error(`Unauthorized ${syntheticKey}`), [syntheticKey]);
  assert.equal(result.category, 'AUTHENTICATION');
  assert.equal(result.message.includes(syntheticKey), false);
});
