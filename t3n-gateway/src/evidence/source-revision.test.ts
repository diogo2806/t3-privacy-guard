import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { resolveSourceRevision } from './source-revision.js';

const SHA = 'a'.repeat(40);

test('resolves a full commit sha and clean tree state from git in development', () => {
  const calls: string[][] = [];
  const revision = resolveSourceRevision('/repo', (args) => {
    calls.push([...args]);
    if (args[0] === 'rev-parse') return SHA;
    return '';
  }, {});

  assert.deepEqual(revision, { sourceCommitSha: SHA, sourceTreeClean: true });
  assert.deepEqual(calls, [
    ['rev-parse', '--verify', 'HEAD'],
    ['status', '--porcelain=v1', '--untracked-files=normal'],
  ]);
});

test('records dirty git source state without hiding it', () => {
  const revision = resolveSourceRevision(
    '/repo',
    (args) => args[0] === 'rev-parse' ? SHA : ' M frontend/src/App.tsx',
    {},
  );
  assert.equal(revision.sourceTreeClean, false);
});

test('uses immutable runtime source metadata without invoking git', () => {
  const directory = mkdtempSync(join(tmpdir(), 't3-evidence-source-'));
  const metadataPath = join(directory, 'source-revision.json');
  writeFileSync(metadataPath, JSON.stringify({ sourceCommitSha: SHA, sourceTreeClean: true }), 'utf8');
  try {
    const revision = resolveSourceRevision('/repo', () => {
      throw new Error('git must not be used when runtime metadata exists');
    }, { EVIDENCE_SOURCE_REVISION_FILE: metadataPath });
    assert.deepEqual(revision, { sourceCommitSha: SHA, sourceTreeClean: true });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('accepts explicit deployment source metadata when no file is configured', () => {
  const revision = resolveSourceRevision('/repo', () => {
    throw new Error('git must not be used for explicit deployment metadata');
  }, {
    EVIDENCE_SOURCE_COMMIT_SHA: SHA.toUpperCase(),
    EVIDENCE_SOURCE_TREE_CLEAN: 'false',
  });
  assert.deepEqual(revision, { sourceCommitSha: SHA, sourceTreeClean: false });
});

test('rejects abbreviated or malformed source commit sha', () => {
  assert.throws(
    () => resolveSourceRevision('/repo', (args) => args[0] === 'rev-parse' ? 'abc1234' : '', {}),
    /full 40-character Git SHA/,
  );
});

test('fails closed when runtime source metadata is incomplete or missing', () => {
  assert.throws(
    () => resolveSourceRevision('/repo', () => '', { EVIDENCE_SOURCE_COMMIT_SHA: SHA }),
    /must be configured together/,
  );
  assert.throws(
    () => resolveSourceRevision('/repo', () => '', { EVIDENCE_SOURCE_REVISION_FILE: '/missing/source-revision.json' }),
    /Unable to read immutable evidence source revision metadata/,
  );
});
