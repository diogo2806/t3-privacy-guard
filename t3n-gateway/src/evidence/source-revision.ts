import { spawnSync } from 'node:child_process';

export interface SourceRevision {
  sourceCommitSha: string;
  sourceTreeClean: boolean;
}

type GitRunner = (args: readonly string[]) => string;

function defaultGitRunner(repositoryRoot: string): GitRunner {
  return (args) => {
    const result = spawnSync('git', [...args], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (result.status !== 0) {
      const detail = (result.stderr || '').trim();
      throw new Error(`Unable to resolve evidence source revision${detail ? `: ${detail}` : ''}`);
    }
    return (result.stdout || '').trim();
  };
}

export function resolveSourceRevision(repositoryRoot: string, git: GitRunner = defaultGitRunner(repositoryRoot)): SourceRevision {
  const sourceCommitSha = git(['rev-parse', '--verify', 'HEAD']).trim();
  if (!/^[a-f0-9]{40}$/.test(sourceCommitSha)) {
    throw new Error('Evidence source commit must be a full 40-character Git SHA');
  }
  const status = git(['status', '--porcelain=v1', '--untracked-files=normal']);
  return {
    sourceCommitSha,
    sourceTreeClean: status.trim().length === 0,
  };
}
