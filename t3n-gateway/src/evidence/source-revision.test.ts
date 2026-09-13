import assert from 'node:assert/strict';
import test from 'node:test';
import { resolveSourceRevision } from './source-revision.js';

const SHA = 'a'.repeat(40);

test('resolves a full commit sha and clean tree state', () => {
  const calls: string[][] = [];
  const revision = resolveSourceRevision('/repo', (args) => {
    calls.push([...args]);
    if (args[0] === 'rev-parse') return SHA;
    return '';
  });

  assert.deepEqual(revision, { sourceCommitSha: SHA, sourceTreeClean: true });
  assert.deepEqual(calls, [
    ['rev-parse', '--verify', 'HEAD'],
    ['status', '--porcelain=v1', '--untracked-files=normal'],
  ]);
});

test('records dirty source state without hiding it', () => {
  const revision = resolveSourceRevision('/repo', (args) => args[0] === 'rev-parse' ? SHA : ' M frontend/src/App.tsx');
  assert.equal(revision.sourceTreeClean, false);
});

test('rejects abbreviated or malformed source commit sha', () => {
  assert.throws(
    () => resolveSourceRevision('/repo', (args) => args[0] === 'rev-parse' ? 'abc1234' : ''),
    /full 40-character Git SHA/,
  );
});
