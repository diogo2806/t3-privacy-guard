import {
  T3nClient,
  createEthAuthInput,
  eth_get_address,
  fetchTrustedManifest,
  loadWasmComponent,
  metamask_sign,
  setEnvironment,
} from '@terminal3/t3n-sdk';
import type { T3nNetwork } from '../config/env.js';

export interface AuthenticatedPrincipal {
  readonly client: T3nClient;
  readonly did: string;
}

export async function authenticatePrincipal(apiKey: string, network: T3nNetwork): Promise<AuthenticatedPrincipal> {
  setEnvironment(network);
  const wasmComponent = await loadWasmComponent();
  const address = eth_get_address(apiKey);
  const trustAnchor = await fetchTrustedManifest(network);
  const client = new T3nClient({
    trustAnchor,
    wasmComponent,
    handlers: {
      EthSign: metamask_sign(address, undefined, apiKey),
    },
  });

  await client.handshake();
  const did = await client.authenticate(createEthAuthInput(address));
  return { client, did: did.value };
}
