import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { readGatewayConfig } from '../config/env.js';
import { assertPolicyVersionImmutable, canonicalizeOperationalPolicy, type CanonicalOperationalPolicy } from '../policy/policy-document.js';
import {
  activateOperationalPolicy,
  ensureImmutablePolicyVersion,
  parsePersistedPolicy,
  readOptionalPolicyEntry,
} from '../policy/policy-map-bootstrap.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import {
  ensureAdministrativePrivateMap,
  readAdministrativePrivateMapEntry,
  writeAndVerifyAdministrativePrivateMapEntry,
} from '../t3n/administrative-private-map.js';
import { T3nSession } from '../t3n/session.js';

const configuredNumericContractId = Number(process.env.T3N_CONTRACT_NUMERIC_ID);
const numericContractId = Number.isInteger(configuredNumericContractId) && configuredNumericContractId > 0
  ? configuredNumericContractId
  : null;

const config = readGatewayConfig();
const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const session = new T3nSession(config, trustFloorStore);
await session.connect();
const tenant = new TenantClient({ t3n: session.getClient(), baseUrl: getNodeUrl(), tenantDid: session.getTenantDid() });
await tenant.tenant.me();

const mapTail = 'privacy-guard-policy';
const mapName = tenant.canonicalName(mapTail);
const getEntry = async (key: string): Promise<string | null> => readAdministrativePrivateMapEntry(tenant, mapTail, key);
const setEntry = async (key: string, value: string): Promise<void> =>
  writeAndVerifyAdministrativePrivateMapEntry(tenant, mapTail, key, value);

let currentEntry: string | null;
if (numericContractId !== null) {
  await ensureAdministrativePrivateMap(tenant, mapTail, numericContractId);
  currentEntry = await readOptionalPolicyEntry(getEntry, 'current');
} else {
  try {
    currentEntry = await getEntry('current');
  } catch (error) {
    if (error instanceof Error && error.name === 'AdministrativePrivateMapError') throw error;
    throw new Error('privacy-guard-policy is unavailable; T3N_CONTRACT_NUMERIC_ID is required to create the private policy map safely');
  }
}

const previous = parsePersistedPolicy(currentEntry, 'Current policy entry');
const rollbackVersion = process.env.T3N_POLICY_ROLLBACK_VERSION?.trim() || null;
let target: CanonicalOperationalPolicy;
let operation: 'publish' | 'rollback';

if (rollbackVersion) {
  if (!/^[A-Za-z0-9._:-]{1,64}$/.test(rollbackVersion)) throw new Error('T3N_POLICY_ROLLBACK_VERSION is invalid');
  const stored = parsePersistedPolicy(
    await readOptionalPolicyEntry(getEntry, `version:${rollbackVersion}`),
    `Stored policy version ${rollbackVersion}`,
  );
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
  await ensureImmutablePolicyVersion(target, getEntry, setEntry);
}

await activateOperationalPolicy(target, getEntry, setEntry);

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
