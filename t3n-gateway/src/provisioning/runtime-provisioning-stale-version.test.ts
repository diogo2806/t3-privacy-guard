import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { resolveOrRegisterContract, type RuntimeProvisioningState } from './runtime-provisioning.js';

test('post-registration verification observes the fresh contract version without process restart', async () => {
  const directory = await mkdtemp(join(tmpdir(), 't3pg-stale-version-'));
  const statePath = join(directory, 'runtime-state.json');
  const wasmPath = join(directory, 'privacy-guard.wasm');
  const tenantDid = 'did:t3n:tenant123';
  const contractId = 'z:tenant123:privacy-guard';
  const identities = [
    { contractId, contractVersion: '0.4.4' },
    { contractId, contractVersion: '0.4.5' },
  ];
  const persistedRemote: RuntimeProvisioningState[] = [];
  let registerCalls = 0;

  try {
    await writeFile(wasmPath, new Uint8Array([0, 97, 115, 109]));
    const result = await resolveOrRegisterContract(
      { contractTail: 'privacy-guard', contractVersion: '0.4.5' } as unknown as Parameters<typeof resolveOrRegisterContract>[0],
      { getTenantDid: () => tenantDid } as unknown as Parameters<typeof resolveOrRegisterContract>[1],
      {
        canonicalContractId: async () => contractId,
        identity: async () => {
          const identity = identities.shift();
          if (!identity) throw new Error('unexpected identity lookup');
          return identity;
        },
      } as unknown as Parameters<typeof resolveOrRegisterContract>[2],
      {
        T3N_RUNTIME_PROVISIONING_STATE_PATH: statePath,
        T3N_CONTRACT_WASM_PATH: wasmPath,
      },
      {
        registerContract: async (request) => {
          registerCalls += 1;
          assert.equal(request.version, '0.4.5');
          return { contract_id: 1059 };
        },
        persistRemoteProvisioningState: async (state) => { persistedRemote.push(state); },
      },
    );

    assert.equal(registerCalls, 1);
    assert.equal(result.registered, true);
    assert.equal(result.contractVersion, '0.4.5');
    assert.equal(result.numericContractId, 1059);
    assert.equal(persistedRemote[0]?.contractVersion, '0.4.5');
    assert.equal(persistedRemote[0]?.numericContractId, 1059);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
