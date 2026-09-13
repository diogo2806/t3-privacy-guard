import { createHash } from 'node:crypto';
import { getNodeUrl } from '@terminal3/t3n-sdk';
import type { AgentSession } from './agent-session.js';

const AGENT_CARD_TYPE = 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';
const MAX_AGENT_CARD_BYTES = 16 * 1024;
const CANONICAL_DID = /^did:t3n:[0-9a-f]{40}$/;
const SENSITIVE_KEY = /(api[_-]?key|private[_-]?key|secret|password|credential|token)/i;
const PRIVATE_KEY_VALUE = /^0x[0-9a-f]{64}$/i;

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

export function buildAgentCard(agentDid: string): PublicAgentCard {
  assertCanonicalDid(agentDid);
  const card: PublicAgentCard = {
    type: AGENT_CARD_TYPE,
    name: 'T3 Privacy Guard',
    description: 'Privacy-preserving incident response agent enforced by T3N policy and protected egress.',
    services: [{ name: 'DID', endpoint: agentDid, version: 'v1' }],
    x402Support: false,
    active: true,
    registrations: [],
    supportedTrust: [],
  };
  assertAgentCardIsSafe(card);
  return card;
}

export function buildAgentCardForSession(agentSession: Pick<AgentSession, 'getAgentDid'>): PublicAgentCard {
  return buildAgentCard(agentSession.getAgentDid());
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

export function validateResolvedAgentCard(agentDid: string, body: string): readonly string[] {
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
  if (card.description !== 'Privacy-preserving incident response agent enforced by T3N policy and protected egress.') throw new Error('Resolved agent card description does not match this agent');
  if (card.active !== undefined && card.active !== true) throw new Error('Resolved agent card is not active');
  if (card.x402Support === true) throw new Error('Resolved agent card claims unsupported x402 capability');
  if (!Array.isArray(card.services) || card.services.length === 0) throw new Error('Resolved agent card has no services');

  const serviceNames: string[] = [];
  let didMatches = 0;
  for (const rawService of card.services) {
    const service = asRecord(rawService);
    if (!service || typeof service.name !== 'string' || typeof service.endpoint !== 'string' || typeof service.version !== 'string') {
      throw new Error('Resolved agent card contains a malformed service');
    }
    serviceNames.push(service.name);
    if (service.name !== 'DID') throw new Error(`Resolved agent card advertises unsupported service: ${service.name}`);
    if (service.version !== 'v1') throw new Error('Resolved DID service has an unsupported version');
    if (service.endpoint !== agentDid) throw new Error('Resolved agent card DID does not match the authenticated Agent DID');
    didMatches += 1;
  }
  if (didMatches !== 1) throw new Error('Resolved agent card must contain exactly one DID service for the authenticated Agent DID');
  return [...new Set(serviceNames)].sort();
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
  ) {}

  async verify(): Promise<AgentRegistrationStatus> {
    const verifiedAt = new Date().toISOString();
    let agentDid: string;
    try {
      agentDid = this.agentSession.getAgentDid();
      assertCanonicalDid(agentDid);
    } catch {
      return { agentDid: '', state: 'UNAVAILABLE', cardUri: null, cardSha256: null, verifiedAt, services: [] };
    }

    let cardUri: string;
    try {
      cardUri = publicCardUri(this.nodeUrl(), agentDid);
    } catch {
      return { agentDid, state: 'UNAVAILABLE', cardUri: null, cardSha256: null, verifiedAt, services: [] };
    }

    try {
      const response = await this.fetchCard(cardUri, {
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(3_000),
      });
      if (response.status === 404) {
        return { agentDid, state: 'NOT_REGISTERED', cardUri: null, cardSha256: null, verifiedAt, services: [] };
      }
      if (!response.ok) {
        return { agentDid, state: 'UNAVAILABLE', cardUri: null, cardSha256: null, verifiedAt, services: [] };
      }

      const body = await response.text();
      const cardSha256 = sha256(body);
      try {
        const services = validateResolvedAgentCard(agentDid, body);
        return { agentDid, state: 'REGISTERED', cardUri, cardSha256, verifiedAt, services };
      } catch {
        return { agentDid, state: 'MISMATCH', cardUri, cardSha256, verifiedAt, services: [] };
      }
    } catch {
      return { agentDid, state: 'UNAVAILABLE', cardUri: null, cardSha256: null, verifiedAt, services: [] };
    }
  }
}
