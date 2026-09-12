import assert from 'node:assert/strict';
import test from 'node:test';
import { assertNoSecretLeak } from './leak-detector.js';

const sentinel = 'SYNTHETIC_SENTINEL_SECRET_FOR_TESTS';

test('accepts evidence that does not contain protected material', () => {
  assert.doesNotThrow(() => assertNoSecretLeak('{"status":"PASS"}', [sentinel]));
});

test('fails when evidence contains the synthetic sentinel secret', () => {
  assert.throws(
    () => assertNoSecretLeak(`{"body":"${sentinel}"}`, [sentinel]),
    /forbidden secret material/,
  );
});

test('fails fast for unsafe short sentinel configuration', () => {
  assert.throws(
    () => assertNoSecretLeak('{"status":"PASS"}', ['short']),
    /at least 6 characters/,
  );
});
