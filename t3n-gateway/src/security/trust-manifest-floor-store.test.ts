import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { TrustManifestFloorStore, TrustManifestFloorStoreError } from './trust-manifest-floor-store.js';

async function fixture(): Promise<{ directory: string; path: string }> {
  const directory = await mkdtemp(join(tmpdir(), 't3n-trust-floor-'));
  return { directory, path: join(directory, 'floor.json') };
}

test('bootstraps an absent store and persists only network, version and timestamp metadata', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new TrustManifestFloorStore(path, () => new Date('2026-09-12T22:00:00.000Z'));

  assert.equal(await store.get('testnet'), null);
  const accepted = await store.recordAccepted('testnet', 7);
  assert.deepEqual(accepted, { network: 'testnet', version: 7, acceptedAt: '2026-09-12T22:00:00.000Z' });
  assert.deepEqual(JSON.parse(await readFile(path, 'utf8')), [accepted]);
});

test('keeps separate monotonic floors per network and never lowers an accepted version', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new TrustManifestFloorStore(path);

  await store.recordAccepted('testnet', 9);
  await store.recordAccepted('production', 4);
  await store.recordAccepted('testnet', 11);
  assert.equal((await store.get('testnet'))?.version, 11);
  assert.equal((await store.get('production'))?.version, 4);

  await assert.rejects(() => store.recordAccepted('testnet', 10), TrustManifestFloorStoreError);
  assert.equal((await store.get('testnet'))?.version, 11);
});

test('serializes concurrent updates so the highest accepted version wins', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new TrustManifestFloorStore(path);

  await Promise.all([store.recordAccepted('testnet', 12), store.recordAccepted('testnet', 13)]);
  assert.equal((await store.get('testnet'))?.version, 13);
});

test('fails closed when an existing store is malformed or contains unsupported metadata', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = new TrustManifestFloorStore(path);

  await writeFile(path, '{not-json', 'utf8');
  await assert.rejects(() => store.get('testnet'), /corrupt; refusing to authenticate/);

  await writeFile(path, JSON.stringify([{ network: 'testnet', version: 3, acceptedAt: new Date().toISOString(), peerIds: ['secret-ish-extra'] }]), 'utf8');
  await assert.rejects(() => store.get('testnet'), /corrupt; refusing to authenticate/);
});

test('does not rewrite the file when the same version is accepted again', async (t) => {
  const { directory, path } = await fixture();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const firstTime = '2026-09-12T22:00:00.000Z';
  let now = new Date(firstTime);
  const store = new TrustManifestFloorStore(path, () => now);

  await store.recordAccepted('testnet', 8);
  now = new Date('2026-09-12T23:00:00.000Z');
  const repeated = await store.recordAccepted('testnet', 8);
  assert.equal(repeated.acceptedAt, firstTime);
  assert.equal((JSON.parse(await readFile(path, 'utf8')) as Array<{ acceptedAt: string }>)[0]?.acceptedAt, firstTime);
});
