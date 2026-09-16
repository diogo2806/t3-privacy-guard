import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, relative, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const sourceDir = dirname(fileURLToPath(import.meta.url));
const gatewayRoot = resolve(sourceDir, '..');
const repositoryRoot = resolve(gatewayRoot, '..');
const canonicalRoot = resolve(repositoryRoot, 'contracts/privacy-guard');
const mirroredRoot = resolve(gatewayRoot, 'contract-source');
const mirroredEntries = ['Cargo.toml', 'src', 'wit'] as const;

async function collectFiles(root: string, entry: string): Promise<string[]> {
  const absolute = resolve(root, entry);
  const directoryEntries = await readdir(absolute, { withFileTypes: true }).catch(() => null);

  if (directoryEntries === null) {
    return [entry];
  }

  const files: string[] = [];
  for (const directoryEntry of directoryEntries) {
    const child = resolve(absolute, directoryEntry.name);
    if (directoryEntry.isDirectory()) {
      files.push(...await collectFiles(root, relative(root, child)));
    } else if (directoryEntry.isFile()) {
      files.push(relative(root, child));
    }
  }
  return files.sort();
}

test('gateway contract build context mirrors the canonical contract source', async () => {
  for (const entry of mirroredEntries) {
    if (entry === 'Cargo.toml') {
      const [canonical, mirrored] = await Promise.all([
        readFile(resolve(canonicalRoot, entry)),
        readFile(resolve(mirroredRoot, entry)),
      ]);
      assert.deepEqual(mirrored, canonical, `${entry} is out of sync; run npm run contract:sync-build-context`);
      continue;
    }

    const [canonicalFiles, mirroredFiles] = await Promise.all([
      collectFiles(canonicalRoot, entry),
      collectFiles(mirroredRoot, entry),
    ]);
    assert.deepEqual(mirroredFiles, canonicalFiles, `${entry} file set is out of sync; run npm run contract:sync-build-context`);

    for (const file of canonicalFiles) {
      const [canonical, mirrored] = await Promise.all([
        readFile(resolve(canonicalRoot, file)),
        readFile(resolve(mirroredRoot, file)),
      ]);
      assert.deepEqual(mirrored, canonical, `${file} is out of sync; run npm run contract:sync-build-context`);
    }
  }
});
