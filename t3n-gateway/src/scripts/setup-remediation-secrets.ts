import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { readGatewayConfig } from '../config/env.js';
import { T3nSession } from '../t3n/session.js';

const numericContractId = Number(process.env.T3N_CONTRACT_NUMERIC_ID);
const securityApiKey = process.env.SECURITY_API_KEY?.trim();
const securityApiUrl = process.env.SECURITY_API_URL?.trim();
if (!Number.isInteger(numericContractId) || numericContractId <= 0) throw new Error('T3N_CONTRACT_NUMERIC_ID is required after contract registration');
if (!securityApiKey) throw new Error('SECURITY_API_KEY is required at setup time');
if (!securityApiUrl?.startsWith('https://')) throw new Error('SECURITY_API_URL must be an HTTPS URL');

const config = readGatewayConfig();
const session = new T3nSession(config);
await session.connect();
const tenant = new TenantClient({ t3n: session.getClient(), baseUrl: getNodeUrl(), tenantDid: session.getTenantDid() });
await tenant.tenant.me();

try {
  await tenant.maps.create({ tail: 'secrets', visibility: 'private', writers: { only: [numericContractId] }, readers: { only: [numericContractId] } });
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  if (!message.toLowerCase().includes('already')) throw error;
}
const mapName = tenant.canonicalName('secrets');
await tenant.executeControl('map-entry-set', { map_name: mapName, key: 'security_api_key', value: securityApiKey });
await tenant.executeControl('map-entry-set', { map_name: mapName, key: 'security_api_url', value: securityApiUrl });
console.info(JSON.stringify({ mapName, contractId: numericContractId, seededKeys: ['security_api_key', 'security_api_url'] }));
