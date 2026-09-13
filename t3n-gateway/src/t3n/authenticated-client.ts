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
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';

export interface AuthenticatedPrincipal {
  readonly client: T3nClient;
  readonly did: string;
  readonly trustManifestVersion: number;
}

export async function authenticatePrincipal(
  apiKey: string,
  network: T3nNetwork,
  trustFloorStore: TrustManifestFloorStore,
): Promise<AuthenticatedPrincipal> {
  setEnvironment(network);
  const persistedFloor = await trustFloorStore.get(network);
  const trustAnchor = await fetchTrustedManifest(
    network,
    persistedFloor ? { minVersion: persistedFloor.version } : undefined,
  );
  const trustManifestVersion = trustAnchor.source?.manifest_version;
  if (!Number.isSafeInteger(trustManifestVersion) || (trustManifestVersion as number) < 1) {
    throw new Error('Verified T3N trust manifest did not expose a valid monotonic manifest version');
  }
  await trustFloorStore.recordAccepted(network, trustManifestVersion as number);

  const wasmComponent = await loadWasmComponent();
  const address = eth_get_address(apiKey);
  const client = new T3nClient({
    trustAnchor,
    wasmComponent,
    handlers: {
      EthSign: metamask_sign(address, undefined, apiKey),
    },
  });

  await client.handshake();
  const did = await client.authenticate(createEthAuthInput(address));
  return { client, did: did.value, trustManifestVersion: trustManifestVersion as number };
}
