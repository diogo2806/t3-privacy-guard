import assert from 'node:assert/strict';
import test from 'node:test';
import type { TenantClient } from '@terminal3/t3n-sdk';
import {
  AdministrativePrivateMapError,
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
      assert.ok(error instanceof AdministrativePrivateMapError);
      assert.equal(error.diagnosticCode, 'ACCESS_DENIED');
      assert.equal(error.message, 'T3N read failed for secrets private map: access denied');
      assert.equal(error.message.includes('raw-secret-value'), false);
      return true;
    },
  );
  await assert.rejects(
    () => writeAndVerifyAdministrativePrivateMapEntry(tenant, 'secrets', 'security_api_key', 'raw-secret-value'),
    (error: unknown) => {
      assert.ok(error instanceof AdministrativePrivateMapError);
      assert.equal(error.diagnosticCode, 'ACCESS_DENIED');
      assert.equal(error.message, 'T3N write failed for secrets private map: access denied');
      assert.equal(error.message.includes('raw-secret-value'), false);
      return true;
    },
  );
});

test('administrative entry writes preserve insufficient-credit diagnosis without exposing account data or secrets', async () => {
  const tenant = {
    maps: {
      entrySet: async () => {
        throw new Error('InsufficientCreditError: InsufficientCredit account=tenant-secret required=10000000000 available=0 SECURITY_API_KEY=raw-secret-value httpStatus=403');
      },
      entryGet: async () => null,
    },
  } as unknown as TenantClient;

  await assert.rejects(
    () => writeAndVerifyAdministrativePrivateMapEntry(tenant, 'privacy-guard-policy', 'current', 'raw-secret-value'),
    (error: unknown) => {
      assert.ok(error instanceof AdministrativePrivateMapError);
      assert.equal(error.diagnosticCode, 'INSUFFICIENT_CREDIT');
      assert.equal(
        error.message,
        'T3N write failed for privacy-guard-policy private map: insufficient credit; replenish T3N account credits and retry',
      );
      assert.equal(error.message.includes('tenant-secret'), false);
      assert.equal(error.message.includes('10000000000'), false);
      assert.equal(error.message.includes('raw-secret-value'), false);
      return true;
    },
  );
});

test('administrative entry read-back mismatch remains distinct from RPC failures', async () => {
  const tenant = {
    maps: {
      entrySet: async () => undefined,
      entryGet: async () => 'different-value',
    },
  } as unknown as TenantClient;

  await assert.rejects(
    () => writeAndVerifyAdministrativePrivateMapEntry(tenant, 'privacy-guard-policy', 'current', 'expected-value'),
    (error: unknown) => {
      assert.ok(error instanceof AdministrativePrivateMapError);
      assert.equal(error.diagnosticCode, 'READ_BACK_MISMATCH');
      assert.equal(error.message, 'T3N read-back mismatch for privacy-guard-policy private map after administrative write');
      assert.equal(error.message.includes('expected-value'), false);
      assert.equal(error.message.includes('different-value'), false);
      return true;
    },
  );
});

test('administrative entry access keeps authentication and network categories sanitized', async () => {
  const authenticationTenant = {
    maps: {
      entryGet: async () => { throw new Error('AuthenticationError SECURITY_API_KEY=raw-secret-value'); },
    },
  } as unknown as TenantClient;
  const networkTenant = {
    maps: {
      entryGet: async () => { throw new Error('fetch failed ECONNRESET raw-secret-value'); },
    },
  } as unknown as TenantClient;

  await assert.rejects(
    () => readAdministrativePrivateMapEntry(authenticationTenant, 'secrets', 'security_api_key'),
    (error: unknown) => {
      assert.ok(error instanceof AdministrativePrivateMapError);
      assert.equal(error.diagnosticCode, 'AUTHENTICATION');
      assert.equal(error.message, 'T3N read failed for secrets private map: authentication rejected');
      assert.equal(error.message.includes('raw-secret-value'), false);
      return true;
    },
  );
  await assert.rejects(
    () => readAdministrativePrivateMapEntry(networkTenant, 'secrets', 'security_api_key'),
    (error: unknown) => {
      assert.ok(error instanceof AdministrativePrivateMapError);
      assert.equal(error.diagnosticCode, 'NETWORK');
      assert.equal(error.message, 'T3N read failed for secrets private map: network unavailable');
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
      assert.ok(error instanceof AdministrativePrivateMapError);
      assert.equal(error.diagnosticCode, 'UNKNOWN');
      assert.equal(error.message, 'Unable to reconcile ACL for privacy-guard-policy private map administratively');
      assert.equal(error.message.includes('StorageRouterOnBehalfOf'), false);
      return true;
    },
  );
});
