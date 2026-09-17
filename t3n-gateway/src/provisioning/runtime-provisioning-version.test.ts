import assert from 'node:assert/strict';
import test from 'node:test';
import { PACKAGED_CONTRACT_VERSION } from '../config/contract-version.js';
import { contractVersionAction } from './runtime-provisioning.js';

test('packaged 0.4.5 recovery registers 0.4.4 and reuses 0.4.5', () => {
  assert.equal(PACKAGED_CONTRACT_VERSION, '0.4.5');
  assert.equal(contractVersionAction('0.4.4', PACKAGED_CONTRACT_VERSION), 'REGISTER');
  assert.equal(contractVersionAction('0.4.5', PACKAGED_CONTRACT_VERSION), 'REUSE');
});

test('packaged 0.4.5 recovery fails closed when T3N is newer', () => {
  assert.throws(
    () => contractVersionAction('0.4.6', PACKAGED_CONTRACT_VERSION),
    /newer than packaged/,
  );
});
