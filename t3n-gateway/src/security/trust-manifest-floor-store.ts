import { randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { T3nNetwork } from '../config/env.js';

export interface TrustManifestFloorRecord {
  readonly network: T3nNetwork;
  readonly version: number;
  readonly acceptedAt: string;
}

export class TrustManifestFloorStoreError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'TrustManifestFloorStoreError';
  }
}

export class TrustManifestFloorStore {
  private tail: Promise<void> = Promise.resolve();

  constructor(private readonly path: string, private readonly now: () => Date = () => new Date()) {
    if (!path.trim()) throw new TrustManifestFloorStoreError('Trust manifest floor store path must not be empty');
  }

  async get(network: T3nNetwork): Promise<TrustManifestFloorRecord | null> {
    return this.exclusive(async () => (await this.readRecords()).find((record) => record.network === network) ?? null);
  }

  async recordAccepted(network: T3nNetwork, version: number): Promise<TrustManifestFloorRecord> {
    return this.exclusive(async () => {
      assertVersion(version);
      const records = await this.readRecords();
      const current = records.find((record) => record.network === network);
      if (current && version < current.version) {
        throw new TrustManifestFloorStoreError(`Verified trust manifest version ${version} is below persisted ${network} floor ${current.version}`);
      }
      if (current && version === current.version) return current;

      const accepted: TrustManifestFloorRecord = {
        network,
        version,
        acceptedAt: this.now().toISOString(),
      };
      const next = [...records.filter((record) => record.network !== network), accepted]
        .sort((left, right) => left.network.localeCompare(right.network));
      await this.writeAtomic(next);
      return accepted;
    });
  }

  private async readRecords(): Promise<TrustManifestFloorRecord[]> {
    let raw: string;
    try {
      raw = await readFile(this.path, 'utf8');
    } catch (error) {
      if (isNodeError(error) && error.code === 'ENOENT') return [];
      throw new TrustManifestFloorStoreError('Unable to read persisted T3N trust manifest floor', { cause: error });
    }

    try {
      const parsed = JSON.parse(raw) as unknown;
      if (!Array.isArray(parsed) || parsed.length > 2) throw new Error('expected an array with at most one record per supported network');
      const records = parsed.map(validateRecord);
      if (new Set(records.map((record) => record.network)).size !== records.length) throw new Error('duplicate network floor');
      return records;
    } catch (error) {
      throw new TrustManifestFloorStoreError('Persisted T3N trust manifest floor is corrupt; refusing to authenticate', { cause: error });
    }
  }

  private async writeAtomic(records: TrustManifestFloorRecord[]): Promise<void> {
    const directory = dirname(this.path);
    await mkdir(directory, { recursive: true });
    const temporaryPath = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    let file: Awaited<ReturnType<typeof open>> | null = null;
    try {
      file = await open(temporaryPath, 'wx', 0o600);
      await file.writeFile(`${JSON.stringify(records, null, 2)}\n`, 'utf8');
      await file.sync();
      await file.close();
      file = null;
      await rename(temporaryPath, this.path);

      try {
        const directoryHandle = await open(directory, 'r');
        try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
      } catch (error) {
        if (!(isNodeError(error) && typeof error.code === 'string' && ['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code))) throw error;
      }
    } catch (error) {
      if (file) await file.close().catch(() => undefined);
      await rm(temporaryPath, { force: true }).catch(() => undefined);
      throw error instanceof TrustManifestFloorStoreError
        ? error
        : new TrustManifestFloorStoreError('Unable to persist T3N trust manifest floor atomically', { cause: error });
    }
  }

  private async exclusive<T>(operation: () => Promise<T>): Promise<T> {
    let release!: () => void;
    const previous = this.tail;
    this.tail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try { return await operation(); } finally { release(); }
  }
}

function validateRecord(value: unknown): TrustManifestFloorRecord {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('floor record must be an object');
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join(',') !== 'acceptedAt,network,version') throw new Error('floor record contains unsupported fields');
  if (record.network !== 'testnet' && record.network !== 'production') throw new Error('invalid network');
  assertVersion(record.version);
  if (typeof record.acceptedAt !== 'string' || !record.acceptedAt.trim() || Number.isNaN(Date.parse(record.acceptedAt))) throw new Error('invalid acceptedAt');
  return { network: record.network, version: record.version, acceptedAt: record.acceptedAt };
}

function assertVersion(value: unknown): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new TrustManifestFloorStoreError('Trust manifest version must be a positive safe integer');
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && 'code' in error;
}
