import { randomUUID } from 'node:crypto';
import { mkdir, open, readFile, rename } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { T3nNetwork } from '../config/env.js';

const SCHEMA_VERSION = 1;
const MAX_MANIFEST_VERSION = Number.MAX_SAFE_INTEGER;

type NetworkRecord = { minVersion: number; updatedAt: string };
type StoreDocument = {
  schemaVersion: 1;
  networks: Partial<Record<T3nNetwork, NetworkRecord>>;
};

export class TrustManifestFloorError extends Error {
  constructor(readonly code: 'TRUST_FLOOR_CORRUPTED' | 'TRUST_FLOOR_WRITE_FAILED' | 'TRUST_MANIFEST_ROLLBACK' | 'TRUST_MANIFEST_VERSION_UNAVAILABLE', message: string) {
    super(message);
    this.name = 'TrustManifestFloorError';
  }
}

function validateVersion(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) < 0 || Number(value) > MAX_MANIFEST_VERSION) {
    throw new TrustManifestFloorError('TRUST_FLOOR_CORRUPTED', 'Persisted T3N trust manifest floor is invalid');
  }
  return Number(value);
}

function validateDocument(value: unknown): StoreDocument {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TrustManifestFloorError('TRUST_FLOOR_CORRUPTED', 'Persisted T3N trust floor is not a JSON object');
  }
  const object = value as Record<string, unknown>;
  if (object.schemaVersion !== SCHEMA_VERSION || !object.networks || typeof object.networks !== 'object' || Array.isArray(object.networks)) {
    throw new TrustManifestFloorError('TRUST_FLOOR_CORRUPTED', 'Persisted T3N trust floor schema is invalid');
  }
  const networks = object.networks as Record<string, unknown>;
  const unknownNetworks = Object.keys(networks).filter((key) => key !== 'testnet' && key !== 'production');
  if (unknownNetworks.length > 0) throw new TrustManifestFloorError('TRUST_FLOOR_CORRUPTED', 'Persisted T3N trust floor contains an unknown network');

  const parsed: StoreDocument = { schemaVersion: 1, networks: {} };
  for (const network of ['testnet', 'production'] as const) {
    const raw = networks[network];
    if (raw === undefined) continue;
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      throw new TrustManifestFloorError('TRUST_FLOOR_CORRUPTED', `Persisted T3N trust floor for ${network} is invalid`);
    }
    const record = raw as Record<string, unknown>;
    const minVersion = validateVersion(record.minVersion);
    if (typeof record.updatedAt !== 'string' || Number.isNaN(Date.parse(record.updatedAt))) {
      throw new TrustManifestFloorError('TRUST_FLOOR_CORRUPTED', `Persisted T3N trust floor timestamp for ${network} is invalid`);
    }
    parsed.networks[network] = { minVersion, updatedAt: record.updatedAt };
  }
  return parsed;
}

export interface TrustFloorSnapshot {
  readonly network: T3nNetwork;
  readonly minVersion: number | null;
  readonly persisted: boolean;
  readonly updatedAt: string | null;
}

export class TrustManifestFloorStore {
  private operation: Promise<unknown> = Promise.resolve();

  constructor(private readonly path: string) {
    if (!path.trim()) throw new Error('T3N trust floor store path must not be empty');
  }

  snapshot(network: T3nNetwork): Promise<TrustFloorSnapshot> {
    return this.serialized(async () => {
      const document = await this.readDocument();
      const record = document.networks[network];
      return { network, minVersion: record?.minVersion ?? null, persisted: Boolean(record), updatedAt: record?.updatedAt ?? null };
    });
  }

  accept(network: T3nNetwork, acceptedVersion: number): Promise<TrustFloorSnapshot> {
    if (!Number.isSafeInteger(acceptedVersion) || acceptedVersion < 0 || acceptedVersion > MAX_MANIFEST_VERSION) {
      return Promise.reject(new TrustManifestFloorError('TRUST_MANIFEST_VERSION_UNAVAILABLE', 'Verified T3N trust manifest version is unavailable or invalid'));
    }
    return this.serialized(async () => {
      const document = await this.readDocument();
      const current = document.networks[network];
      if (current && acceptedVersion < current.minVersion) {
        throw new TrustManifestFloorError('TRUST_MANIFEST_ROLLBACK', 'Verified T3N trust manifest is older than the persisted trust floor');
      }
      if (current && acceptedVersion === current.minVersion) {
        return { network, minVersion: current.minVersion, persisted: true, updatedAt: current.updatedAt };
      }
      const updatedAt = new Date().toISOString();
      document.networks[network] = { minVersion: acceptedVersion, updatedAt };
      await this.atomicWrite(document);
      return { network, minVersion: acceptedVersion, persisted: true, updatedAt };
    });
  }

  private serialized<T>(work: () => Promise<T>): Promise<T> {
    const next = this.operation.then(work, work);
    this.operation = next.then(() => undefined, () => undefined);
    return next;
  }

  private async readDocument(): Promise<StoreDocument> {
    let raw: string;
    try {
      raw = await readFile(this.path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { schemaVersion: 1, networks: {} };
      throw new TrustManifestFloorError('TRUST_FLOOR_CORRUPTED', 'Persisted T3N trust floor cannot be read safely');
    }
    try {
      return validateDocument(JSON.parse(raw));
    } catch (error) {
      if (error instanceof TrustManifestFloorError) throw error;
      throw new TrustManifestFloorError('TRUST_FLOOR_CORRUPTED', 'Persisted T3N trust floor contains invalid JSON');
    }
  }

  private async atomicWrite(document: StoreDocument): Promise<void> {
    const directory = dirname(this.path);
    const temporary = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    let handle: Awaited<ReturnType<typeof open>> | null = null;
    try {
      await mkdir(directory, { recursive: true });
      handle = await open(temporary, 'wx', 0o600);
      await handle.writeFile(`${JSON.stringify(document, null, 2)}\n`, 'utf8');
      await handle.sync();
      await handle.close();
      handle = null;
      await rename(temporary, this.path);
      try {
        const directoryHandle = await open(directory, 'r');
        try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== 'EINVAL' && code !== 'ENOTSUP' && code !== 'EISDIR') throw error;
      }
    } catch {
      if (handle) await handle.close().catch(() => undefined);
      throw new TrustManifestFloorError('TRUST_FLOOR_WRITE_FAILED', 'Verified T3N trust manifest floor could not be persisted safely');
    }
  }
}
