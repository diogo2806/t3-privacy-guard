import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseContractRegistrationResult,
  registerContractWithDurableId,
  type ContractRegistrationClient,
} from './t3n-contract-registrar.js';

const CONTRACT_ID = 'z:tenant123:privacy-guard';

test('registration response accepts positive safe integer ids', () => {
  assert.deepEqual(
    parseContractRegistrationResult(JSON.stringify({ name: CONTRACT_ID, contract_id: 42 }), CONTRACT_ID),
    { name: CONTRACT_ID, contract_id: 42 },
  );
  assert.deepEqual(
    parseContractRegistrationResult(JSON.stringify({ name: CONTRACT_ID, contract_id: '43' }), CONTRACT_ID),
    { name: CONTRACT_ID, contract_id: 43 },
  );
});

test('registration response rejects unsafe or ambiguous ids', () => {
  const rejected = [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1, '0', '-1', '1.5', '1e3', '0x2a', ' 42', '42 ', '0042', 'abc'];
  for (const contractId of rejected) {
    assert.throws(
      () => parseContractRegistrationResult(JSON.stringify({ name: CONTRACT_ID, contract_id: contractId }), CONTRACT_ID),
      /invalid numeric contract id/,
    );
  }
});

test('registration response rejects malformed payload and canonical id mismatch', () => {
  assert.throws(() => parseContractRegistrationResult('not-json', CONTRACT_ID), /invalid response/);
  assert.throws(
    () => parseContractRegistrationResult(JSON.stringify({ name: 'z:other:privacy-guard', contract_id: 42 }), CONTRACT_ID),
    /unexpected canonical contract id/,
  );
});

test('low-level registration sends the canonical contract-register request and normalizes the id', async () => {
  let capturedRequest: Parameters<ContractRegistrationClient['executeWithBlob']>[0] | null = null;
  let capturedBlobSize = 0;
  const client: ContractRegistrationClient = {
    executeWithBlob: async (request, blob) => {
      capturedRequest = request;
      capturedBlobSize = blob.size;
      return JSON.stringify({ name: CONTRACT_ID, contract_id: '88' });
    },
  };

  const result = await registerContractWithDurableId({
    client,
    canonicalContractId: CONTRACT_ID,
    version: '0.4.5',
    wasm: new Uint8Array([0, 97, 115, 109]),
    resolveTenantContractsVersion: async () => '1.26.0',
  });

  assert.equal(result.contract_id, 88);
  assert.equal(result.name, CONTRACT_ID);
  assert.equal(capturedBlobSize, 4);
  assert.deepEqual(capturedRequest, {
    script_name: 'tee:tenant/contracts',
    script_version: '1.26.0',
    function_name: 'contract-register',
    input: {
      name: CONTRACT_ID,
      version: '0.4.5',
    },
  });
});
