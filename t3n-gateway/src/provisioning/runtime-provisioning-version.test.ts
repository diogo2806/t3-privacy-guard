import assert from 'node:assert/strict';
import test from 'node:test';
import { PACKAGED_CONTRACT_VERSION } from '../config/contract-version.js';
import { contractVersionAction } from './runtime-provisioning.js';

test('packaged 1.0.0 migration registers 0.4.5 and reuses 1.0.0', () => {
  assert.equal(PACKAGED_CONTRACT_VERSION, '1.0.0');
  assert.equal(contractVersionAction('0.4.5', PACKAGED_CONTRACT_VERSION), 'REGISTER');
  assert.equal(contractVersionAction('1.0.0', PACKAGED_CONTRACT_VERSION), 'REUSE');
});

test('packaged 1.0.0 migration fails closed when T3N is newer', () => {
  assert.throws(
    () => contractVersionAction('1.0.1', PACKAGED_CONTRACT_VERSION),
    /newer than packaged/,
  );
});
