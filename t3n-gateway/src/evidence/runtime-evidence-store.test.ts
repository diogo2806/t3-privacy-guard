import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { readRuntimeEvidenceBundle, runtimeEvidencePaths } from './runtime-evidence-store.js';

async function withDirectory(run: (directory: string) => Promise<void>): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), 't3-runtime-evidence-'));
  try { await run(directory); } finally { await rm(directory, { recursive: true, force: true }); }
}

test('runtime evidence is absent only when both files are absent', async () => {
  await withDirectory(async (directory) => {
    const result = await readRuntimeEvidenceBundle({ EVIDENCE_RUNTIME_DIR: directory });
    assert.deepEqual(result, { state: 'ABSENT', manifest: null, testnet: null });
  });
});

test('runtime evidence is invalid when only one side exists', async () => {
  await withDirectory(async (directory) => {
    await writeFile(join(directory, 'deployment-manifest.json'), '{}', 'utf8');
    const result = await readRuntimeEvidenceBundle({ EVIDENCE_RUNTIME_DIR: directory });
    assert.equal(result.state, 'INVALID');
  });
});

test('runtime evidence returns parsed paired objects', async () => {
  await withDirectory(async (directory) => {
    await mkdir(directory, { recursive: true });
    await writeFile(join(directory, 'deployment-manifest.json'), JSON.stringify({ source: 'T3N_TESTNET' }), 'utf8');
    await writeFile(join(directory, 'testnet-run.json'), JSON.stringify({ scenarios: [] }), 'utf8');
    const result = await readRuntimeEvidenceBundle({ EVIDENCE_RUNTIME_DIR: directory });
    assert.equal(result.state, 'AVAILABLE');
    assert.deepEqual(result.manifest, { source: 'T3N_TESTNET' });
    assert.deepEqual(result.testnet, { scenarios: [] });
  });
});

test('runtime evidence rejects malformed json and empty files', async () => {
  await withDirectory(async (directory) => {
    await writeFile(join(directory, 'deployment-manifest.json'), '{', 'utf8');
    await writeFile(join(directory, 'testnet-run.json'), '', 'utf8');
    const result = await readRuntimeEvidenceBundle({ EVIDENCE_RUNTIME_DIR: directory });
    assert.equal(result.state, 'INVALID');
  });
});

test('explicit evidence paths override the runtime directory', () => {
  assert.deepEqual(runtimeEvidencePaths({
    EVIDENCE_RUNTIME_DIR: '/data/evidence',
    EVIDENCE_DEPLOYMENT_MANIFEST: '/mounted/manifest.json',
    EVIDENCE_OUTPUT: '/mounted/run.json',
  }), {
    manifestPath: '/mounted/manifest.json',
    testnetPath: '/mounted/run.json',
  });
});
