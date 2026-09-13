import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { TenantClient, getNodeUrl } from '@terminal3/t3n-sdk';
import { readGatewayConfig } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

const config = readGatewayConfig();
const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const session = new T3nSession(config, trustFloorStore);
await session.connect();

const tenant = new TenantClient({
  t3n: session.getClient(),
  baseUrl: getNodeUrl(),
  tenantDid: session.getTenantDid(),
});
await tenant.tenant.me();

const wasmPath = resolve(process.env.T3N_CONTRACT_WASM_PATH ?? '../contracts/privacy-guard/target/wasm32-wasip2/release/privacy_guard_contract.wasm');
const wasm = await readFile(wasmPath);
const result = await tenant.contracts.register({
  tail: config.contractTail,
  version: config.contractVersion,
  wasm,
});

const tenantId = session.getTenantDid().slice('did:t3n:'.length);
console.info(JSON.stringify({
  contractId: `z:${tenantId}:${config.contractTail}`,
  numericContractId: result.contract_id,
  version: config.contractVersion,
  wasmPath,
}, null, 2));
