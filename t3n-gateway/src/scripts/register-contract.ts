import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { readGatewayConfig } from '../config/env.js';
import { registerContractWithDurableId } from '../contract/t3n-contract-registrar.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { T3nSession } from '../t3n/session.js';

const config = readGatewayConfig();
const trustFloorStore = new TrustManifestFloorStore(config.trustManifestFloorStorePath);
const session = new T3nSession(config, trustFloorStore);
await session.connect();

const wasmPath = resolve(process.env.T3N_CONTRACT_WASM_PATH ?? '../contracts/privacy-guard/target/wasm32-wasip2/release/privacy_guard_contract.wasm');
const wasm = await readFile(wasmPath);
const tenantId = session.getTenantDid().slice('did:t3n:'.length);
const contractId = `z:${tenantId}:${config.contractTail}`;
const result = await registerContractWithDurableId({
  client: session.getClient(),
  canonicalContractId: contractId,
  version: config.contractVersion,
  wasm,
});

console.info(JSON.stringify({
  contractId,
  numericContractId: result.contract_id,
  version: config.contractVersion,
  wasmPath,
}, null, 2));
