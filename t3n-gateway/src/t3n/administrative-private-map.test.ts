import assert from 'node:assert/strict';
import test from 'node:test';
import type { TenantClient } from '@terminal3/t3n-sdk';
import {
  administrativePrivateMapAcl,
  ensureAdministrativePrivateMap,
} from './administrative-private-map.js';

test('administrative private map ACL denies contract writes and restricts reads to the contract', () => {
  assert.deepEqual(administrativePrivateMapAcl(1059), {
    writers: { only: [] },
    readers: { only: [1059] },
  });
});

test('administrative private map ACL rejects invalid contract ids', () => {
  assert.throws(() => administrativePrivateMapAcl(0), /positive integer/);
  assert.throws(() => administrativePrivateMapAcl(-1), /positive integer/);
  assert.throws(() => administrativePrivateMapAcl(1.5), /positive integer/);
});

test('administrative private map creation stays private and never adds broad principals', async () => {
  const calls: unknown[] = [];
  const tenant = {
    canonicalName: (tail: string) => `z:tenant:${tail}`,
    maps: {
      create: async (input: unknown) => { calls.push(input); },
      update: async () => { throw new Error('update should not be called'); },
    },
  } as unknown as TenantClient;

  const name = await ensureAdministrativePrivateMap(tenant, 'privacy-guard-policy', 1059);

  assert.equal(name, 'z:tenant:privacy-guard-policy');
  assert.deepEqual(calls, [{
    tail: 'privacy-guard-policy',
    visibility: 'private',
    writers: { only: [] },
    readers: { only: [1059] },
  }]);
});

test('existing administrative private maps are re-ACLed idempotently before control-plane writes', async () => {
  const updates: unknown[] = [];
  const tenant = {
    canonicalName: (tail: string) => `z:tenant:${tail}`,
    maps: {
      create: async () => { throw new Error('Map already exists'); },
      update: async (tail: string, acl: unknown) => { updates.push({ tail, acl }); },
    },
  } as unknown as TenantClient;

  await ensureAdministrativePrivateMap(tenant, 'secrets', 1059);
  await ensureAdministrativePrivateMap(tenant, 'secrets', 1059);

  assert.deepEqual(updates, [
    {
      tail: 'secrets',
      acl: { writers: { only: [] }, readers: { only: [1059] } },
    },
    {
      tail: 'secrets',
      acl: { writers: { only: [] }, readers: { only: [1059] } },
    },
  ]);
});

test('ACL reconciliation sanitizes raw T3N access-denied details', async () => {
  const tenant = {
    canonicalName: (tail: string) => `z:tenant:${tail}`,
    maps: {
      create: async () => { throw new Error('Map already exists'); },
      update: async () => {
        throw new Error('StorageRouterOnBehalfOf(Contract(tee:tenant/contracts)) cannot write map');
      },
    },
  } as unknown as TenantClient;

  await assert.rejects(
    () => ensureAdministrativePrivateMap(tenant, 'privacy-guard-policy', 1059),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, 'Unable to reconcile privacy-guard-policy private map ACL safely');
      assert.equal(error.message.includes('StorageRouterOnBehalfOf'), false);
      return true;
    },
  );
});
