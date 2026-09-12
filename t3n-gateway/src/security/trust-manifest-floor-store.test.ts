import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { TrustManifestFloorError, TrustManifestFloorStore } from './trust-manifest-floor-store.js';

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), 't3n-trust-floor-'));
  return { directory, path: join(directory, 'floor.json') };
}

test('missing file bootstraps normally and persists accepted version', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new TrustManifestFloorStore(path);

  assert.deepEqual(await store.snapshot('testnet'), { network: 'testnet', minVersion: null, persisted: false, updatedAt: null });
  const accepted = await store.accept('testnet', 100);
  assert.equal(accepted.minVersion, 100);
  assert.equal(accepted.persisted, true);

  const afterRestart = new TrustManifestFloorStore(path);
  assert.equal((await afterRestart.snapshot('testnet')).minVersion, 100);
});

test('same version succeeds, newer version advances and older version fails closed', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new TrustManifestFloorStore(path);

  await store.accept('testnet', 100);
  assert.equal((await store.accept('testnet', 100)).minVersion, 100);
  assert.equal((await store.accept('testnet', 101)).minVersion, 101);
  await assert.rejects(
    () => new TrustManifestFloorStore(path).accept('testnet', 100),
    (error: unknown) => error instanceof TrustManifestFloorError && error.code === 'TRUST_MANIFEST_ROLLBACK',
  );
  assert.equal((await new TrustManifestFloorStore(path).snapshot('testnet')).minVersion, 101);
});

test('testnet and production floors are isolated in one shared file', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new TrustManifestFloorStore(path);
  await store.accept('testnet', 101);
  await store.accept('production', 700);

  assert.equal((await store.snapshot('testnet')).minVersion, 101);
  assert.equal((await store.snapshot('production')).minVersion, 700);
});

test('concurrent tenant and agent updates cannot regress the shared floor', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new TrustManifestFloorStore(path);

  const results = await Promise.allSettled([
    store.accept('testnet', 102),
    store.accept('testnet', 100),
    store.accept('testnet', 101),
    store.accept('testnet', 103),
  ]);
  assert.ok(results.some((result) => result.status === 'rejected'));
  assert.equal((await store.snapshot('testnet')).minVersion, 103);
});

test('corrupted, truncated and unknown-network documents fail closed instead of resetting the floor', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));

  for (const raw of [
    '{',
    JSON.stringify({ schemaVersion: 1, networks: { testnet: { minVersion: '100', updatedAt: new Date().toISOString() } } }),
    JSON.stringify({ schemaVersion: 1, networks: { staging: { minVersion: 100, updatedAt: new Date().toISOString() } } }),
  ]) {
    await writeFile(path, raw, 'utf8');
    await assert.rejects(
      () => new TrustManifestFloorStore(path).snapshot('testnet'),
      (error: unknown) => error instanceof TrustManifestFloorError && error.code === 'TRUST_FLOOR_CORRUPTED',
    );
  }
});

test('persisted file contains only public trust metadata', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new TrustManifestFloorStore(path);
  await store.accept('testnet', 1787800421);

  const raw = await readFile(path, 'utf8');
  assert.match(raw, /1787800421/);
  for (const forbidden of ['T3N_API_KEY', 'T3N_AGENT_API_KEY', 'privateKey', 'cookie', 'session']) {
    assert.equal(raw.includes(forbidden), false);
  }
});
