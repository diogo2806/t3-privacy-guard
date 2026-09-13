import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { readGatewayConfig } from '../config/env.js';
import { authorizationPublicKeyFingerprint } from '../security/remediation-authorization.js';
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

async function ensurePrivateContractMap(tail: string): Promise<string> {
  try {
    await tenant.maps.create({ tail, visibility: 'private', writers: { only: [numericContractId] }, readers: { only: [numericContractId] } });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!message.toLowerCase().includes('already')) throw error;
  }
  return tenant.canonicalName(tail);
}

const secretsMapName = await ensurePrivateContractMap('secrets');
await tenant.executeControl('map-entry-set', { map_name: secretsMapName, key: 'security_api_key', value: securityApiKey });
await tenant.executeControl('map-entry-set', { map_name: secretsMapName, key: 'security_api_url', value: securityApiUrl });
await tenant.executeControl('map-entry-set', { map_name: secretsMapName, key: 'security_verification_url', value: securityVerificationUrl });
const verificationKeyEntry = `remediation_auth_public_key_spki:${config.remediationAuthorizationKeyId}`;
await tenant.executeControl('map-entry-set', {
  map_name: secretsMapName,
  key: verificationKeyEntry,
  value: config.remediationAuthorizationPublicKeySpki,
});

const replayMapName = await ensurePrivateContractMap('privacy-guard-execution-nonces');
console.info(JSON.stringify({
  secretsMapName,
  replayMapName,
  contractId: numericContractId,
  seededKeys: ['security_api_key', 'security_api_url', 'security_verification_url', verificationKeyEntry],
  remediationAuthorizationKeyId: config.remediationAuthorizationKeyId,
  remediationAuthorizationPublicKeyFingerprint: authorizationPublicKeyFingerprint(config.remediationAuthorizationPublicKeySpki),
}));
