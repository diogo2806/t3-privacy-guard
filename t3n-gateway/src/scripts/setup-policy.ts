import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { readGatewayConfig } from '../config/env.js';
import { assertPolicyVersionImmutable, canonicalizeOperationalPolicy, type CanonicalOperationalPolicy } from '../policy/policy-document.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

const configuredNumericContractId = Number(process.env.T3N_CONTRACT_NUMERIC_ID);
const numericContractId = Number.isInteger(configuredNumericContractId) && configuredNumericContractId > 0
  ? configuredNumericContractId
  : null;

function extractValue(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8');
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  for (const key of ['value', 'data', 'result']) {
    const extracted = extractValue(record[key]);
    if (extracted != null) return extracted;
  }
  return null;
}

function parsePersistedPolicy(value: string | null, label: string): CanonicalOperationalPolicy | null {
  if (!value) return null;
  try {
    return canonicalizeOperationalPolicy(JSON.parse(value) as unknown);
  } catch {
    throw new Error(`${label} contains an invalid operational policy`);
  }
}

const config = readGatewayConfig();
const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const session = new T3nSession(config, trustFloorStore);
await session.connect();
const tenant = new TenantClient({ t3n: session.getClient(), baseUrl: getNodeUrl(), tenantDid: session.getTenantDid() });
await tenant.tenant.me();

const mapTail = 'privacy-guard-policy';
const mapName = tenant.canonicalName(mapTail);
const executeControl = tenant.executeControl.bind(tenant) as (name: string, input: Record<string, string>) => Promise<unknown>;
const getEntry = async (key: string): Promise<string | null> => extractValue(await executeControl('map-entry-get', { map_name: mapName, key }));
const getOptionalEntry = async (key: string): Promise<string | null> => {
  try {
    return await getEntry(key);
  } catch {
    return null;
  }
};
const setEntry = async (key: string, value: string): Promise<void> => {
  await tenant.executeControl('map-entry-set', { map_name: mapName, key, value });
};

let currentEntry: string | null;
if (numericContractId !== null) {
  const restrictedAcl = {
    writers: { only: [numericContractId] },
    readers: { only: [numericContractId] },
  };
  try {
    await tenant.maps.create({
      tail: mapTail,
      visibility: 'private',
      ...restrictedAcl,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.toLowerCase().includes('already')) throw error;
    await tenant.maps.update(mapTail, restrictedAcl);
  }
  currentEntry = await getOptionalEntry('current');
} else {
  try {
    currentEntry = await getEntry('current');
  } catch {
    throw new Error('privacy-guard-policy is unavailable; T3N_CONTRACT_NUMERIC_ID is required to create the private policy map safely');
  }
}

const previous = parsePersistedPolicy(currentEntry, 'Current policy entry');
const rollbackVersion = process.env.T3N_POLICY_ROLLBACK_VERSION?.trim() || null;
let target: CanonicalOperationalPolicy;
let operation: 'publish' | 'rollback';

if (rollbackVersion) {
  if (!/^[A-Za-z0-9._:-]{1,64}$/.test(rollbackVersion)) throw new Error('T3N_POLICY_ROLLBACK_VERSION is invalid');
  const stored = parsePersistedPolicy(await getOptionalEntry(`version:${rollbackVersion}`), `Stored policy version ${rollbackVersion}`);
  if (!stored) throw new Error(`Policy version ${rollbackVersion} is not stored and cannot be rolled back`);
  if (stored.document.version !== rollbackVersion) throw new Error('Stored rollback policy version does not match its immutable KV key');
  target = stored;
  operation = 'rollback';
} else {
  const policyPath = resolve(process.cwd(), process.env.T3N_POLICY_FILE ?? 'policy/privacy-guard-policy.json');
  const raw = await readFile(policyPath, 'utf8');
  if (Buffer.byteLength(raw, 'utf8') > 32 * 1024) throw new Error('Operational policy exceeds 32 KiB');
  target = canonicalizeOperationalPolicy(JSON.parse(raw) as unknown);
  operation = 'publish';

  assertPolicyVersionImmutable(previous, target);
  const versionKey = `version:${target.document.version}`;
  const storedVersion = parsePersistedPolicy(await getOptionalEntry(versionKey), `Stored policy version ${target.document.version}`);
  assertPolicyVersionImmutable(storedVersion, target);
  if (!storedVersion) await setEntry(versionKey, target.canonicalJson);
}

await setEntry('current', target.canonicalJson);
const verified = parsePersistedPolicy(await getEntry('current'), 'Policy read-back');
if (!verified) throw new Error('Policy read-back returned no value');
if (verified.document.version !== target.document.version || verified.hash !== target.hash) {
  throw new Error('Policy read-back version/hash mismatch');
}

const changedAt = new Date().toISOString();
const auditRecord = JSON.stringify({
  operation,
  changedAt,
  previousVersion: previous?.document.version ?? null,
  previousHash: previous?.hash ?? null,
  policyVersion: target.document.version,
  policyHash: target.hash,
});
await setEntry(`history:${Date.now()}:${target.hash.slice(0, 12)}`, auditRecord);

console.info(JSON.stringify({
  operation,
  mapName,
  contractId: numericContractId,
  previousPolicyVersion: previous?.document.version ?? null,
  previousPolicyHash: previous?.hash ?? null,
  policyVersion: target.document.version,
  policyHash: target.hash,
  verifiedReadBack: true,
  auditRecordedAt: changedAt,
}, null, 2));
