import {
  T3nClient,
  createEthAuthInput,
  discoverCheckDelegation,
  discoverWhoami,
  eth_get_address,
  fetchTrustedManifest,
  getNodeUrl,
  invoke,
  loadWasmComponent,
  metamask_sign,
  setEnvironment,
} from '@terminal3/t3n-sdk';
import type { T3nNetwork } from '../config/env.js';
import { TrustManifestFloorStore } from '../security/trust-manifest-floor-store.js';
import { classifyPrincipalCredential } from './principal-credential.js';

export interface PrincipalExecutionRequest<TInput = unknown> {
  readonly contract_id: string;
  readonly contract_version: string;
  readonly function_name: string;
  readonly pii_did: string;
  readonly input: TInput;
}

export interface PrincipalDelegationCheckRequest {
  readonly contract: string;
  readonly pii_did: string;
  readonly functions: string[];
  readonly scopes: string[];
}

export interface AuthenticatedPrincipal {
  readonly client: T3nClient;
  readonly did: string;
  readonly trustManifestVersion: number;
}

export interface AuthenticatedOrgAgentPrincipal {
  readonly did: string;
  readonly trustManifestVersion: number;
}

const CANONICAL_DID_PATTERN = /^did:t3n:[A-Za-z0-9]+$/;

async function loadVerifiedTrustManifest(
  network: T3nNetwork,
  trustFloorStore: TrustManifestFloorStore,
): Promise<{ trustAnchor: Awaited<ReturnType<typeof fetchTrustedManifest>>; trustManifestVersion: number }> {
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
  return { trustAnchor, trustManifestVersion: trustManifestVersion as number };
}

export async function authenticatePrincipal(
  apiKey: string,
  network: T3nNetwork,
  trustFloorStore: TrustManifestFloorStore,
): Promise<AuthenticatedPrincipal> {
  if (classifyPrincipalCredential(apiKey) !== 'secp256k1') {
    throw new Error('Session authentication requires a secp256k1 private key credential');
  }

  const { trustAnchor, trustManifestVersion } = await loadVerifiedTrustManifest(network, trustFloorStore);
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
  return { client, did: did.value, trustManifestVersion };
}

export async function authenticateOrgAgentPrincipal(
  apiKey: string,
  network: T3nNetwork,
  trustFloorStore: TrustManifestFloorStore,
): Promise<AuthenticatedOrgAgentPrincipal> {
  if (classifyPrincipalCredential(apiKey) !== 'org-agent') {
    throw new Error('Organization-owned agent authentication requires a t3n_key credential');
  }

  const { trustManifestVersion } = await loadVerifiedTrustManifest(network, trustFloorStore);
  const who = await discoverWhoami({ baseUrl: getNodeUrl(), apiKey });
  if (!CANONICAL_DID_PATTERN.test(who.did)) {
    throw new Error('T3N organization-owned agent authentication did not return a canonical DID');
  }
  return { did: who.did, trustManifestVersion };
}

export async function invokeOrgAgent<T>(
  apiKey: string,
  network: T3nNetwork,
  request: PrincipalExecutionRequest,
): Promise<T> {
  if (classifyPrincipalCredential(apiKey) !== 'org-agent') {
    throw new Error('Stateless invoke requires a t3n_key organization-owned agent credential');
  }
  setEnvironment(network);
  return invoke({ baseUrl: getNodeUrl(), apiKey, request }) as Promise<T>;
}

export async function checkOrgAgentDelegation(
  apiKey: string,
  network: T3nNetwork,
  request: PrincipalDelegationCheckRequest,
): Promise<unknown> {
  if (classifyPrincipalCredential(apiKey) !== 'org-agent') {
    throw new Error('Stateless delegation check requires a t3n_key organization-owned agent credential');
  }
  setEnvironment(network);
  return discoverCheckDelegation({ baseUrl: getNodeUrl(), apiKey }, request);
}
