import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { readGatewayConfig } from '../config/env.js';
import { canonicalizeOperationalPolicy } from '../policy/policy-document.js';
import { T3nSession } from '../t3n/session.js';

const numericContractId = Number(process.env.T3N_CONTRACT_NUMERIC_ID);
if (!Number.isInteger(numericContractId) || numericContractId <= 0) {
  throw new Error('T3N_CONTRACT_NUMERIC_ID is required after contract registration');
}

const policyPath = resolve(process.cwd(), process.env.T3N_POLICY_FILE ?? 'policy/privacy-guard-policy.json');
const raw = await readFile(policyPath, 'utf8');
if (Buffer.byteLength(raw, 'utf8') > 32 * 1024) throw new Error('Operational policy exceeds 32 KiB');
const canonical = canonicalizeOperationalPolicy(JSON.parse(raw) as unknown);

const config = readGatewayConfig();
const session = new T3nSession(config);
await session.connect();
const tenant = new TenantClient({ t3n: session.getClient(), baseUrl: getNodeUrl(), tenantDid: session.getTenantDid() });
await tenant.tenant.me();

try {
  await tenant.maps.create({
    tail: 'privacy-guard-policy',
    visibility: 'private',
    writers: { only: [numericContractId] },
    readers: { only: [numericContractId] },
  });
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  if (!message.toLowerCase().includes('already')) throw error;
}

const mapName = tenant.canonicalName('privacy-guard-policy');
await tenant.executeControl('map-entry-set', { map_name: mapName, key: 'current', value: canonical.canonicalJson });

const executeControl = tenant.executeControl.bind(tenant) as (name: string, input: Record<string, string>) => Promise<unknown>;
const readBack = await executeControl('map-entry-get', { map_name: mapName, key: 'current' });

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

const persisted = extractValue(readBack);
if (!persisted) throw new Error('Policy read-back returned no value');
const verified = canonicalizeOperationalPolicy(JSON.parse(persisted) as unknown);
if (verified.document.version !== canonical.document.version || verified.hash !== canonical.hash) {
  throw new Error('Policy read-back version/hash mismatch');
}

console.info(JSON.stringify({
  mapName,
  contractId: numericContractId,
  policyVersion: canonical.document.version,
  policyHash: canonical.hash,
  verifiedReadBack: true,
}, null, 2));
