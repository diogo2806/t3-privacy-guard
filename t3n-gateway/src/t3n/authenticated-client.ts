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
import { TrustManifestFloorError, type TrustFloorSnapshot, TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';

export interface AuthenticatedPrincipal {
  readonly client: T3nClient;
  readonly did: string;
  readonly trust: TrustFloorSnapshot & { readonly trustAnchorVerified: true };
}

function verifiedManifestVersion(trustAnchor: unknown): number {
  if (!trustAnchor || typeof trustAnchor !== 'object' || Array.isArray(trustAnchor)) {
    throw new TrustManifestFloorError('TRUST_MANIFEST_VERSION_UNAVAILABLE', 'Verified T3N trust manifest did not expose a version');
  }
  const version = (trustAnchor as Record<string, unknown>).version;
  if (!Number.isSafeInteger(version) || Number(version) < 0) {
    throw new TrustManifestFloorError('TRUST_MANIFEST_VERSION_UNAVAILABLE', 'Verified T3N trust manifest version is unavailable or invalid');
  }
  return Number(version);
}

export async function authenticatePrincipal(
  apiKey: string,
  network: T3nNetwork,
  trustFloorStore: TrustManifestFloorStore,
): Promise<AuthenticatedPrincipal> {
  setEnvironment(network);
  const wasmComponent = await loadWasmComponent();
  const address = eth_get_address(apiKey);
  const before = await trustFloorStore.snapshot(network);
  const trustAnchor = await fetchTrustedManifest(network, before.minVersion === null ? undefined : { minVersion: before.minVersion });
  const acceptedVersion = verifiedManifestVersion(trustAnchor);
  const persistedTrust = await trustFloorStore.accept(network, acceptedVersion);
  const client = new T3nClient({
    trustAnchor,
    wasmComponent,
    handlers: {
      EthSign: metamask_sign(address, undefined, apiKey),
    },
  });

  await client.handshake();
  const did = await client.authenticate(createEthAuthInput(address));
  return { client, did: did.value, trust: { ...persistedTrust, trustAnchorVerified: true } };
}
