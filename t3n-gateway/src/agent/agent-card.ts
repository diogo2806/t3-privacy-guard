import { createHash } from 'node:crypto';
import { getNodeUrl } from '@terminal3/t3n-sdk';
import { validateA2aPublicUrl } from '../config/env.js';
import type { AgentSession } from './agent-session.js';

const AGENT_CARD_TYPE = 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';
const AGENT_CARD_DESCRIPTION = 'Privacy-preserving incident response agent enforced by T3N policy and protected egress.';
const MAX_AGENT_CARD_BYTES = 16 * 1024;
const CANONICAL_DID = /^did:t3n:[0-9a-f]{40}$/;
const SENSITIVE_KEY = /(api[_-]?key|private[_-]?key|secret|password|credential|token)/i;
const PRIVATE_KEY_VALUE = /^0x[0-9a-f]{64}$/i;
const A2A_VERSION = '1.0';

export type AgentRegistrationState = 'REGISTERED' | 'NOT_REGISTERED' | 'MISMATCH' | 'UNAVAILABLE';

export interface AgentCardService {
  readonly name: string;
  readonly endpoint: string;
  readonly version: string;
}

export interface PublicAgentCard {
  readonly type: typeof AGENT_CARD_TYPE;
  readonly name: 'T3 Privacy Guard';
  readonly description: string;
  readonly services: readonly AgentCardService[];
  readonly x402Support: false;
  readonly active: true;
  readonly registrations: readonly unknown[];
  readonly supportedTrust: readonly string[];
}

export interface AgentRegistrationStatus {
  readonly agentDid: string;
  readonly state: AgentRegistrationState;
  readonly cardUri: string | null;
  readonly cardSha256: string | null;
  readonly verifiedAt: string;
  readonly services: readonly string[];
  readonly a2aConfigured: boolean;
  readonly a2aPublicUrl: string | null;
  readonly a2aConfigurationCheckedAt: string;
}

interface HttpResponseLike {
  readonly ok: boolean;
  readonly status: number;
  text(): Promise<string>;
}

export type AgentCardFetch = (
  url: string,
  init: { readonly headers: Readonly<Record<string, string>>; readonly signal: AbortSignal },
) => Promise<HttpResponseLike>;

export type AgentCardNodeUrl = () => string;

function assertCanonicalDid(agentDid: string): void {
  if (!CANONICAL_DID.test(agentDid)) throw new Error('Agent card requires the canonical did:t3n identifier returned by the authenticated session');
}

function assertNoSensitiveMetadata(value: unknown, path = 'card'): void {
  if (typeof value === 'string') {
    if (PRIVATE_KEY_VALUE.test(value)) throw new Error(`Agent card contains private-key-shaped metadata at ${path}`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertNoSensitiveMetadata(entry, `${path}[${index}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (SENSITIVE_KEY.test(key)) throw new Error(`Agent card contains sensitive metadata key at ${path}.${key}`);
    assertNoSensitiveMetadata(child, `${path}.${key}`);
  }
}

function a2aDiscoveryEndpoint(a2aPublicUrl: string): string {
  const validatedPublicUrl = validateA2aPublicUrl(a2aPublicUrl);
  const endpoint = new URL(validatedPublicUrl);
  return new URL('/.well-known/agent-card.json', endpoint.origin).toString();
}

export function buildAgentCard(agentDid: string, a2aPublicUrl: string | null = null): PublicAgentCard {
  assertCanonicalDid(agentDid);
  const services: AgentCardService[] = [{ name: 'DID', endpoint: agentDid, version: 'v1' }];
  if (a2aPublicUrl) services.push({ name: 'A2A', endpoint: a2aDiscoveryEndpoint(a2aPublicUrl), version: A2A_VERSION });
  const card: PublicAgentCard = {
    type: AGENT_CARD_TYPE,
    name: 'T3 Privacy Guard',
    description: AGENT_CARD_DESCRIPTION,
    services,
    x402Support: false,
    active: true,
    registrations: [],
    supportedTrust: [],
  };
  assertAgentCardIsSafe(card);
  return card;
}

export function buildAgentCardForSession(agentSession: Pick<AgentSession, 'getAgentDid'>, a2aPublicUrl: string | null = null): PublicAgentCard {
  return buildAgentCard(agentSession.getAgentDid(), a2aPublicUrl);
}

export function serializeAgentCard(card: PublicAgentCard): string {
  assertAgentCardIsSafe(card);
  return `${JSON.stringify(card, null, 2)}\n`;
}

export function assertAgentCardIsSafe(card: unknown): void {
  assertNoSensitiveMetadata(card);
  const serialized = JSON.stringify(card);
  if (Buffer.byteLength(serialized, 'utf8') > MAX_AGENT_CARD_BYTES) {
    throw new Error('Agent card exceeds the T3N 16 KiB hosted-card limit');
  }
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

export function validateResolvedAgentCard(agentDid: string, body: string, a2aPublicUrl: string | null = null): readonly string[] {
  assertCanonicalDid(agentDid);
  if (Buffer.byteLength(body, 'utf8') > MAX_AGENT_CARD_BYTES) throw new Error('Resolved agent card exceeds the T3N 16 KiB limit');

  let parsed: unknown;
  try {
    parsed = JSON.parse(body) as unknown;
  } catch {
    throw new Error('Resolved agent card is not valid JSON');
  }
  const card = asRecord(parsed);
  if (!card) throw new Error('Resolved agent card must be a JSON object');
  assertNoSensitiveMetadata(card);
  const allowedKeys = new Set(['type', 'name', 'description', 'services', 'x402Support', 'active', 'registrations', 'supportedTrust']);
  for (const key of Object.keys(card)) {
    if (!allowedKeys.has(key)) throw new Error(`Resolved agent card contains unsupported metadata field: ${key}`);
  }

  if (card.type !== AGENT_CARD_TYPE) throw new Error('Resolved agent card has an unsupported registration type');
  if (card.name !== 'T3 Privacy Guard') throw new Error('Resolved agent card name does not match this agent');
  if (card.description !== AGENT_CARD_DESCRIPTION) throw new Error('Resolved agent card description does not match this agent');
  if (card.active !== true) throw new Error('Resolved agent card is not active');
  if (card.x402Support !== false) throw new Error('Resolved agent card must explicitly disable unsupported x402 capability');
  if (!Array.isArray(card.registrations) || card.registrations.length !== 0) throw new Error('Resolved agent card contains unsupported registrations');
  if (!Array.isArray(card.supportedTrust) || card.supportedTrust.length !== 0) throw new Error('Resolved agent card claims unsupported trust evidence');
  if (!Array.isArray(card.services) || card.services.length === 0 || card.services.length > 2) throw new Error('Resolved agent card has an invalid service set');

  const serviceNames: string[] = [];
  const seen = new Set<string>();
  let didMatches = 0;
  let a2aMatches = 0;
  const expectedA2aEndpoint = a2aPublicUrl ? a2aDiscoveryEndpoint(a2aPublicUrl) : null;
  for (const rawService of card.services) {
    const service = asRecord(rawService);
    if (!service || typeof service.name !== 'string' || typeof service.endpoint !== 'string' || typeof service.version !== 'string') {
      throw new Error('Resolved agent card contains a malformed service');
    }
    if (seen.has(service.name)) throw new Error(`Resolved agent card contains duplicate service: ${service.name}`);
    seen.add(service.name);
    serviceNames.push(service.name);

    if (service.name === 'DID') {
      if (service.version !== 'v1') throw new Error('Resolved DID service has an unsupported version');
      if (service.endpoint !== agentDid) throw new Error('Resolved agent card DID does not match the authenticated Agent DID');
      didMatches += 1;
      continue;
    }
    if (service.name === 'A2A') {
      if (!expectedA2aEndpoint) throw new Error('Resolved agent card advertises A2A while A2A_PUBLIC_URL is not configured');
      if (service.version !== A2A_VERSION) throw new Error('Resolved A2A service has an unsupported version');
      if (service.endpoint !== expectedA2aEndpoint) throw new Error('Resolved A2A discovery endpoint does not match local configuration');
      a2aMatches += 1;
      continue;
    }
    throw new Error(`Resolved agent card advertises unsupported service: ${service.name}`);
  }
  if (didMatches !== 1) throw new Error('Resolved agent card must contain exactly one DID service for the authenticated Agent DID');
  if (a2aPublicUrl && a2aMatches !== 1) throw new Error('Resolved agent card must contain the configured A2A service');
  if (!a2aPublicUrl && a2aMatches !== 0) throw new Error('Resolved agent card must not contain an unconfigured A2A service');
  return [...serviceNames].sort();
}

function sha256(body: string): string {
  return createHash('sha256').update(body, 'utf8').digest('hex');
}

function publicCardUri(nodeUrl: string, agentDid: string): string {
  assertCanonicalDid(agentDid);
  const base = new URL(nodeUrl);
  if (base.protocol !== 'https:') throw new Error('T3N public agent-card resolution must use HTTPS');
  base.pathname = `${base.pathname.replace(/\/$/, '')}/api/agent-card/${agentDid}`;
  base.search = '';
  base.hash = '';
  return base.toString();
}

const defaultFetch: AgentCardFetch = async (url, init) => fetch(url, init);

export class AgentCardRegistry {
  constructor(
    private readonly agentSession: AgentSession,
    private readonly fetchCard: AgentCardFetch = defaultFetch,
    private readonly nodeUrl: AgentCardNodeUrl = () => getNodeUrl(),
    private readonly a2aPublicUrl: string | null = null,
  ) {}

  private status(verifiedAt: string, agentDid: string, state: AgentRegistrationState, cardUri: string | null, cardSha256: string | null, services: readonly string[]): AgentRegistrationStatus {
    return {
      agentDid,
      state,
      cardUri,
      cardSha256,
      verifiedAt,
      services,
      a2aConfigured: this.a2aPublicUrl !== null,
      a2aPublicUrl: this.a2aPublicUrl,
      a2aConfigurationCheckedAt: verifiedAt,
    };
  }

  async verify(): Promise<AgentRegistrationStatus> {
    const verifiedAt = new Date().toISOString();
    let agentDid: string;
    try {
      agentDid = this.agentSession.getAgentDid();
      assertCanonicalDid(agentDid);
    } catch {
      return this.status(verifiedAt, '', 'UNAVAILABLE', null, null, []);
    }

    let cardUri: string;
    try {
      cardUri = publicCardUri(this.nodeUrl(), agentDid);
    } catch {
      return this.status(verifiedAt, agentDid, 'UNAVAILABLE', null, null, []);
    }

    try {
      const response = await this.fetchCard(cardUri, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(3_000),
      });
      if (response.status === 404) {
        return this.status(verifiedAt, agentDid, 'NOT_REGISTERED', null, null, []);
      }
      if (!response.ok) {
        return this.status(verifiedAt, agentDid, 'UNAVAILABLE', null, null, []);
      }

      const body = await response.text();
      const cardSha256 = sha256(body);
      try {
        const services = validateResolvedAgentCard(agentDid, body, this.a2aPublicUrl);
        return this.status(verifiedAt, agentDid, 'REGISTERED', cardUri, cardSha256, services);
      } catch {
        return this.status(verifiedAt, agentDid, 'MISMATCH', cardUri, cardSha256, []);
      }
    } catch {
      return this.status(verifiedAt, agentDid, 'UNAVAILABLE', null, null, []);
    }
  }
}
