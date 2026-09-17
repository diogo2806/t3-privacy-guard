import assert from 'node:assert/strict';
import test from 'node:test';
import type { TenantClient } from '@terminal3/t3n-sdk';
import {
  administrativePrivateMapAcl,
  ensureAdministrativePrivateMap,
  readAdministrativePrivateMapEntry,
  writeAndVerifyAdministrativePrivateMapEntry,
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

test('administrative entry reads use the tenant maps owner surface instead of raw control-plane reads', async () => {
  const calls: unknown[] = [];
  const tenant = {
    maps: {
      entryGet: async (tail: string, key: string) => {
        calls.push({ tail, key });
        return 'protected-value';
      },
    },
    executeControl: async () => {
      throw new Error('raw map-entry-get must not be used');
    },
  } as unknown as TenantClient;

  assert.equal(await readAdministrativePrivateMapEntry(tenant, 'secrets', 'security_api_url'), 'protected-value');
  assert.deepEqual(calls, [{ tail: 'secrets', key: 'security_api_url' }]);
});

test('administrative entry writes verify exact read-back through the tenant maps owner surface', async () => {
  const values = new Map<string, string>();
  const tenant = {
    maps: {
      entrySet: async (tail: string, key: string, value: string) => {
        values.set(`${tail}:${key}`, value);
      },
      entryGet: async (tail: string, key: string) => values.get(`${tail}:${key}`) ?? null,
    },
    executeControl: async () => {
      throw new Error('raw map entry controls must not be used');
    },
  } as unknown as TenantClient;

  await writeAndVerifyAdministrativePrivateMapEntry(tenant, 'privacy-guard-policy', 'current', '{"version":"1"}');
  assert.equal(values.get('privacy-guard-policy:current'), '{"version":"1"}');
});

test('administrative entry access sanitizes raw T3N errors and never includes protected values', async () => {
  const tenant = {
    maps: {
      entryGet: async () => {
        throw new Error('AccessDenied raw-secret-value StorageRouterOnBehalfOf');
      },
      entrySet: async () => {
        throw new Error('AccessDenied raw-secret-value StorageRouterOnBehalfOf');
      },
    },
  } as unknown as TenantClient;

  await assert.rejects(
    () => readAdministrativePrivateMapEntry(tenant, 'secrets', 'security_api_key'),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, 'Unable to read secrets private map entry administratively');
      assert.equal(error.message.includes('raw-secret-value'), false);
      return true;
    },
  );
  await assert.rejects(
    () => writeAndVerifyAdministrativePrivateMapEntry(tenant, 'secrets', 'security_api_key', 'raw-secret-value'),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, 'Unable to write and verify secrets private map entry administratively');
      assert.equal(error.message.includes('raw-secret-value'), false);
      return true;
    },
  );
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

test('existing administrative private maps are re-ACLed idempotently before owner writes', async () => {
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
