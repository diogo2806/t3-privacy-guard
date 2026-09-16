import { readFileSync } from 'node:fs';
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

function validateSourceRevision(sourceCommitSha: string, sourceTreeClean: boolean): SourceRevision {
  const normalizedSha = sourceCommitSha.trim().toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(normalizedSha)) {
    throw new Error('Evidence source commit must be a full 40-character Git SHA');
  }
  return { sourceCommitSha: normalizedSha, sourceTreeClean };
}

function parseBoolean(value: string, field: string): boolean {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;
  throw new Error(`${field} must be true or false`);
}

function revisionFromMetadataFile(path: string): SourceRevision {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8')) as unknown;
  } catch {
    throw new Error('Unable to read immutable evidence source revision metadata');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Evidence source revision metadata must be a JSON object');
  }
  const object = parsed as Record<string, unknown>;
  if (typeof object.sourceCommitSha !== 'string' || typeof object.sourceTreeClean !== 'boolean') {
    throw new Error('Evidence source revision metadata is incomplete');
  }
  return validateSourceRevision(object.sourceCommitSha, object.sourceTreeClean);
}

function revisionFromEnvironment(env: NodeJS.ProcessEnv): SourceRevision | null {
  const sha = env.EVIDENCE_SOURCE_COMMIT_SHA?.trim();
  const clean = env.EVIDENCE_SOURCE_TREE_CLEAN?.trim();
  if (!sha && !clean) return null;
  if (!sha || !clean) throw new Error('EVIDENCE_SOURCE_COMMIT_SHA and EVIDENCE_SOURCE_TREE_CLEAN must be configured together');
  return validateSourceRevision(sha, parseBoolean(clean, 'EVIDENCE_SOURCE_TREE_CLEAN'));
}

export function resolveSourceRevision(
  repositoryRoot: string,
  git: GitRunner = defaultGitRunner(repositoryRoot),
  env: NodeJS.ProcessEnv = process.env,
): SourceRevision {
  const deploymentRevision = revisionFromEnvironment(env);
  if (deploymentRevision) return deploymentRevision;

  const metadataPath = env.EVIDENCE_SOURCE_REVISION_FILE?.trim();
  if (metadataPath) return revisionFromMetadataFile(metadataPath);

  const sourceCommitSha = git(['rev-parse', '--verify', 'HEAD']).trim();
  const status = git(['status', '--porcelain=v1', '--untracked-files=normal']);
  return validateSourceRevision(sourceCommitSha, status.trim().length === 0);
}
