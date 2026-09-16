import { readFile, stat } from 'node:fs/promises';
import { resolve } from 'node:path';

const DEFAULT_RUNTIME_EVIDENCE_DIR = '/data/evidence';
const MAX_EVIDENCE_FILE_BYTES = 2 * 1024 * 1024;

export type RuntimeEvidenceState = 'ABSENT' | 'AVAILABLE' | 'INVALID';

export interface RuntimeEvidenceBundle {
  readonly state: RuntimeEvidenceState;
  readonly manifest: unknown | null;
  readonly testnet: unknown | null;
}

export function runtimeEvidencePaths(env: NodeJS.ProcessEnv = process.env): { manifestPath: string; testnetPath: string } {
  const directory = resolve(env.EVIDENCE_RUNTIME_DIR?.trim() || DEFAULT_RUNTIME_EVIDENCE_DIR);
  return {
    manifestPath: resolve(env.EVIDENCE_DEPLOYMENT_MANIFEST?.trim() || resolve(directory, 'deployment-manifest.json')),
    testnetPath: resolve(env.EVIDENCE_OUTPUT?.trim() || resolve(directory, 'testnet-run.json')),
  };
}

async function regularFileState(path: string): Promise<'MISSING' | 'REGULAR' | 'INVALID'> {
  try {
    const metadata = await stat(path);
    if (!metadata.isFile() || metadata.size <= 0 || metadata.size > MAX_EVIDENCE_FILE_BYTES) return 'INVALID';
    return 'REGULAR';
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return 'MISSING';
    return 'INVALID';
  }
}

async function readJson(path: string): Promise<unknown> {
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw) as unknown;
}

export async function readRuntimeEvidenceBundle(env: NodeJS.ProcessEnv = process.env): Promise<RuntimeEvidenceBundle> {
  const { manifestPath, testnetPath } = runtimeEvidencePaths(env);
  const [manifestState, testnetState] = await Promise.all([
    regularFileState(manifestPath),
    regularFileState(testnetPath),
  ]);

  if (manifestState === 'MISSING' && testnetState === 'MISSING') {
    return { state: 'ABSENT', manifest: null, testnet: null };
  }
  if (manifestState !== 'REGULAR' || testnetState !== 'REGULAR') {
    return { state: 'INVALID', manifest: null, testnet: null };
  }

  try {
    const [manifest, testnet] = await Promise.all([readJson(manifestPath), readJson(testnetPath)]);
    if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new Error('invalid manifest');
    if (!testnet || typeof testnet !== 'object' || Array.isArray(testnet)) throw new Error('invalid testnet evidence');
    return { state: 'AVAILABLE', manifest, testnet };
  } catch {
    return { state: 'INVALID', manifest: null, testnet: null };
  }
}
