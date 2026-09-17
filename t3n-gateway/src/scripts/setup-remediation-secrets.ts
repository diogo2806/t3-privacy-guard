import { createPublicKey } from 'node:crypto';
import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { readGatewayConfig, rejectDocumentationPlaceholder } from '../config/env.js';
import { authorizationPublicKeyFingerprint } from '../security/remediation-authorization.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { ensureAdministrativePrivateMap } from '../t3n/administrative-private-map.js';
import { T3nSession } from '../t3n/session.js';

const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,32}$/;
const MAX_PREVIOUS_KEY_GRACE_SECONDS = 300;
const MAP_PROBE_KEY = '__privacy_guard_map_probe__';

const configuredNumericContractId = Number(process.env.T3N_CONTRACT_NUMERIC_ID);
const numericContractId = Number.isInteger(configuredNumericContractId) && configuredNumericContractId > 0
  ? configuredNumericContractId
  : null;
const securityApiKey = process.env.SECURITY_API_KEY?.trim();
const securityApiUrl = process.env.SECURITY_API_URL?.trim();
const securityVerificationUrl = process.env.SECURITY_VERIFICATION_URL?.trim();
if (!securityApiKey) throw new Error('SECURITY_API_KEY is required at setup time');
rejectDocumentationPlaceholder(securityApiKey, 'SECURITY_API_KEY');
if (!securityApiUrl?.startsWith('https://')) throw new Error('SECURITY_API_URL must be an HTTPS URL');
if (!securityVerificationUrl?.startsWith('https://')) throw new Error('SECURITY_VERIFICATION_URL must be an HTTPS URL');

const config = readGatewayConfig();

interface PreviousVerificationKey {
  readonly keyId: string;
  readonly publicKeySpki: string;
  readonly validUntilMs: number;
}

function validateEd25519PublicKey(value: string, name: string): string {
  try {
    const der = Buffer.from(value, 'base64');
    if (!der.length || der.toString('base64') !== value.replace(/\s+/g, '')) throw new Error('invalid base64');
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('wrong key type');
    return value;
  } catch {
    throw new Error(`${name} must be a base64 SPKI Ed25519 public key`);
  }
}

function readPreviousVerificationKey(): PreviousVerificationKey | null {
  const keyId = process.env.REMEDIATION_AUTH_PREVIOUS_KEY_ID?.trim() || null;
  const publicKeySpki = process.env.REMEDIATION_AUTH_PREVIOUS_PUBLIC_KEY_SPKI?.trim() || null;
  const graceRaw = process.env.REMEDIATION_AUTH_PREVIOUS_KEY_GRACE_SECONDS?.trim() || null;
  const configured = [keyId, publicKeySpki, graceRaw].filter((value) => value !== null).length;
  if (configured === 0) return null;
  if (configured !== 3 || !keyId || !publicKeySpki || !graceRaw) {
    throw new Error('REMEDIATION_AUTH_PREVIOUS_KEY_ID, REMEDIATION_AUTH_PREVIOUS_PUBLIC_KEY_SPKI and REMEDIATION_AUTH_PREVIOUS_KEY_GRACE_SECONDS must be configured together');
  }
  if (!KEY_ID_PATTERN.test(keyId)) throw new Error('REMEDIATION_AUTH_PREVIOUS_KEY_ID must match [A-Za-z0-9._-]{1,32}');
  if (keyId === config.remediationAuthorizationKeyId) throw new Error('REMEDIATION_AUTH_PREVIOUS_KEY_ID must differ from REMEDIATION_AUTH_KEY_ID');
  const graceSeconds = Number(graceRaw);
  if (!Number.isInteger(graceSeconds) || graceSeconds < 1 || graceSeconds > MAX_PREVIOUS_KEY_GRACE_SECONDS) {
    throw new Error(`REMEDIATION_AUTH_PREVIOUS_KEY_GRACE_SECONDS must be an integer between 1 and ${MAX_PREVIOUS_KEY_GRACE_SECONDS}`);
  }
  return {
    keyId,
    publicKeySpki: validateEd25519PublicKey(publicKeySpki, 'REMEDIATION_AUTH_PREVIOUS_PUBLIC_KEY_SPKI'),
    validUntilMs: Date.now() + graceSeconds * 1_000,
  };
}

function errorText(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).toLowerCase();
}

function isMapNotFound(error: unknown): boolean {
  const message = errorText(error);
  return message.includes('map not found') || message.includes('map_not_found') || message.includes('map does not exist');
}

function missingMapError(tail: string): Error {
  return new Error(`${tail} private map is unavailable; T3N_CONTRACT_NUMERIC_ID is required to create or repair it safely`);
}

function extractControlValue(value: unknown, depth = 0): string | null {
  if (depth > 4) return null;
  if (typeof value === 'string') return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString('utf8');
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  for (const key of ['value', 'data', 'result']) {
    const extracted = extractControlValue(record[key], depth + 1);
    if (extracted != null) return extracted;
  }
  return null;
}

const previousVerificationKey = readPreviousVerificationKey();
const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const session = new T3nSession(config, trustFloorStore);
await session.connect();
const tenant = new TenantClient({ t3n: session.getClient(), baseUrl: getNodeUrl(), tenantDid: session.getTenantDid() });
await tenant.tenant.me();
const executeControl = tenant.executeControl.bind(tenant) as (name: string, input: Record<string, string>) => Promise<unknown>;

async function ensurePrivateContractMap(tail: string): Promise<string> {
  const mapName = tenant.canonicalName(tail);
  if (numericContractId === null) {
    try {
      await executeControl('map-entry-get', { map_name: mapName, key: MAP_PROBE_KEY });
    } catch (error) {
      if (isMapNotFound(error)) throw missingMapError(tail);
      const message = errorText(error);
      if (!message.includes('not found') && !message.includes('missing')) {
        throw new Error(`Unable to confirm existing ${tail} private map without T3N_CONTRACT_NUMERIC_ID`);
      }
    }
    return mapName;
  }

  return ensureAdministrativePrivateMap(tenant, tail, numericContractId);
}

async function setProtectedEntry(mapName: string, mapTail: string, key: string, value: string): Promise<void> {
  try {
    await executeControl('map-entry-set', { map_name: mapName, key, value });
    const readBack = extractControlValue(await executeControl('map-entry-get', { map_name: mapName, key }));
    if (readBack !== value) throw new Error('read-back mismatch');
  } catch (error) {
    if (isMapNotFound(error) && numericContractId === null) throw missingMapError(mapTail);
    throw new Error(`Unable to seed and verify protected ${mapTail} configuration`);
  }
}

const secretsMapName = await ensurePrivateContractMap('secrets');
const replayMapName = await ensurePrivateContractMap('privacy-guard-execution-nonces');

await setProtectedEntry(secretsMapName, 'secrets', 'security_api_key', securityApiKey);
await setProtectedEntry(secretsMapName, 'secrets', 'security_api_url', securityApiUrl);
await setProtectedEntry(secretsMapName, 'secrets', 'security_verification_url', securityVerificationUrl);
await setProtectedEntry(
  secretsMapName,
  'secrets',
  'remediation_auth_active_key_id',
  config.remediationAuthorizationKeyId,
);
const verificationKeyEntry = `remediation_auth_public_key_spki:${config.remediationAuthorizationKeyId}`;
await setProtectedEntry(
  secretsMapName,
  'secrets',
  verificationKeyEntry,
  config.remediationAuthorizationPublicKeySpki,
);

const seededKeys = [
  'security_api_key',
  'security_api_url',
  'security_verification_url',
  'remediation_auth_active_key_id',
  verificationKeyEntry,
];

if (previousVerificationKey) {
  const previousKeyEntry = `remediation_auth_public_key_spki:${previousVerificationKey.keyId}`;
  const previousExpiryEntry = `remediation_auth_key_valid_until:${previousVerificationKey.keyId}`;
  await setProtectedEntry(
    secretsMapName,
    'secrets',
    previousKeyEntry,
    previousVerificationKey.publicKeySpki,
  );
  await setProtectedEntry(
    secretsMapName,
    'secrets',
    previousExpiryEntry,
    String(previousVerificationKey.validUntilMs),
  );
  seededKeys.push(previousKeyEntry, previousExpiryEntry);
}

console.info(JSON.stringify({
  secretsMapName,
  replayMapName,
  contractId: numericContractId,
  seededKeys,
  remediationAuthorizationKeyId: config.remediationAuthorizationKeyId,
  remediationAuthorizationPublicKeyFingerprint: authorizationPublicKeyFingerprint(config.remediationAuthorizationPublicKeySpki),
  previousRemediationAuthorizationKeyId: previousVerificationKey?.keyId ?? null,
  previousRemediationAuthorizationKeyValidUntilMs: previousVerificationKey?.validUntilMs ?? null,
  previousRemediationAuthorizationPublicKeyFingerprint: previousVerificationKey
    ? authorizationPublicKeyFingerprint(previousVerificationKey.publicKeySpki)
    : null,
}));
