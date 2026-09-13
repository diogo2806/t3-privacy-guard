import { createHash } from 'node:crypto';
import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { readGatewayConfig } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

const numericContractId = Number(process.env.T3N_CONTRACT_NUMERIC_ID);
const securityApiKey = process.env.SECURITY_API_KEY?.trim();
const securityApiUrl = process.env.SECURITY_API_URL?.trim();
const securityVerificationUrl = process.env.SECURITY_VERIFICATION_URL?.trim();
if (!Number.isInteger(numericContractId) || numericContractId <= 0) throw new Error('T3N_CONTRACT_NUMERIC_ID is required after contract registration');
if (!securityApiKey) throw new Error('SECURITY_API_KEY is required at setup time');
if (!securityApiUrl?.startsWith('https://')) throw new Error('SECURITY_API_URL must be an HTTPS URL');
if (!securityVerificationUrl?.startsWith('https://')) throw new Error('SECURITY_VERIFICATION_URL must be an HTTPS URL');

const config = readGatewayConfig();
const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const session = new T3nSession(config, trustFloorStore);
await session.connect();
const tenant = new TenantClient({ t3n: session.getClient(), baseUrl: getNodeUrl(), tenantDid: session.getTenantDid() });
await tenant.tenant.me();

async function ensurePrivateContractMap(tail: string): Promise<void> {
  try {
    await tenant.maps.create({ tail, visibility: 'private', writers: { only: [numericContractId] }, readers: { only: [numericContractId] } });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.toLowerCase().includes('already')) throw error;
  }
}

await ensurePrivateContractMap('secrets');
const secretsMapName = tenant.canonicalName('secrets');
await tenant.executeControl('map-entry-set', { map_name: secretsMapName, key: 'security_api_key', value: securityApiKey });
await tenant.executeControl('map-entry-set', { map_name: secretsMapName, key: 'security_api_url', value: securityApiUrl });
await tenant.executeControl('map-entry-set', { map_name: secretsMapName, key: 'security_verification_url', value: securityVerificationUrl });

await ensurePrivateContractMap('privacy-guard-authorization');
const authorizationMapName = tenant.canonicalName('privacy-guard-authorization');
await tenant.executeControl('map-entry-set', { map_name: authorizationMapName, key: 'active_key_id', value: config.remediationAuthorizationKeyId });
await tenant.executeControl('map-entry-set', {
  map_name: authorizationMapName,
  key: `verification_key:${config.remediationAuthorizationKeyId}`,
  value: config.remediationAuthorizationPublicKey,
});
const verificationKeyFingerprint = createHash('sha256')
  .update(Buffer.from(config.remediationAuthorizationPublicKey, 'hex'))
  .digest('hex');

console.info(JSON.stringify({
  secretsMapName,
  authorizationMapName,
  contractId: numericContractId,
  seededSecretKeys: ['security_api_key', 'security_api_url', 'security_verification_url'],
  authorizationKeyId: config.remediationAuthorizationKeyId,
  verificationKeyFingerprint,
}));
