import { createHash } from 'node:crypto';
import { getNodeUrl, setEnvironment } from '@terminal3/t3n-sdk';
import type { AgentSession } from './agent-session.js';
import type { T3nNetwork } from '../config/env.js';

export const AGENT_CARD_TYPE = 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1';
export const MAX_AGENT_CARD_BYTES = 16 * 1024;

export type AgentRegistrationState = 'REGISTERED' | 'NOT_REGISTERED' | 'MISMATCH' | 'UNAVAILABLE';

export interface AgentCardServiceDescriptor {
  readonly name: 'DID';
  readonly endpoint: string;
  readonly version: 'v1';
}

export interface AgentCard {
  readonly type: typeof AGENT_CARD_TYPE;
  readonly name: 'T3 Privacy Guard';
  readonly description: string;
  readonly services: readonly AgentCardServiceDescriptor[];
  readonly active: true;
}

export interface AgentRegistrationStatus {
  readonly agentDid: string | null;
  readonly agentRegistrationState: AgentRegistrationState;
  readonly agentCardUri: string | null;
  readonly agentCardSha256: string | null;
  readonly agentCardVerifiedAt: string;
  readonly agentCardServices: readonly string[];
}

type FetchLike = (input: string | URL, init?: RequestInit) => Promise<Response>;

function assertCanonicalDid(agentDid: string): void {
  if (!/^did:t3n:[A-Za-z0-9._:-]+$/.test(agentDid)) throw new Error('Agent Card requires a canonical T3N DID');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function servicesFrom(card: Record<string, unknown>): string[] {
  if (!Array.isArray(card.services)) return [];
  return card.services
    .filter(isRecord)
    .map((service) => typeof service.name === 'string' ? service.name : '')
    .filter(Boolean);
}

export function buildAgentCard(agentDid: string): AgentCard {
  assertCanonicalDid(agentDid);
  const card: AgentCard = {
    type: AGENT_CARD_TYPE,
    name: 'T3 Privacy Guard',
    description: 'Privacy-preserving incident response agent enforced by T3N policy and protected egress.',
    services: [{ name: 'DID', endpoint: agentDid, version: 'v1' }],
    active: true,
  };
  assertAgentCardMatches(card, agentDid);
  return card;
}

export function serializeAgentCard(card: AgentCard): string {
  const serialized = `${JSON.stringify(card, null, 2)}\n`;
  if (Buffer.byteLength(serialized, 'utf8') >= MAX_AGENT_CARD_BYTES) throw new Error('Agent Card exceeds the supported 16 KiB limit');
  return serialized;
}

export function assertAgentCardMatches(value: unknown, expectedDid: string): asserts value is AgentCard {
  assertCanonicalDid(expectedDid);
  if (!isRecord(value)) throw new Error('Agent Card must be a JSON object');
  if (value.type !== AGENT_CARD_TYPE) throw new Error('Agent Card registration type is invalid');
  if (value.name !== 'T3 Privacy Guard') throw new Error('Agent Card name does not match this agent');
  if (typeof value.description !== 'string' || value.description.length < 1 || value.description.length > 512) {
    throw new Error('Agent Card description is invalid');
  }
  if (value.active !== true) throw new Error('Agent Card is not active');
  if (!Array.isArray(value.services) || value.services.length !== 1 || !isRecord(value.services[0])) {
    throw new Error('Agent Card must declare exactly the supported DID service');
  }
  const service = value.services[0];
  if (service.name !== 'DID' || service.endpoint !== expectedDid || service.version !== 'v1') {
    throw new Error('Agent Card DID service does not match the authenticated Agent DID');
  }
  const serialized = JSON.stringify(value);
  if (Buffer.byteLength(serialized, 'utf8') >= MAX_AGENT_CARD_BYTES) throw new Error('Agent Card exceeds the supported 16 KiB limit');
}

export class AgentCardRegistrationService {
  constructor(
    private readonly agentSession: AgentSession,
    private readonly network: T3nNetwork,
    private readonly fetcher: FetchLike = fetch,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async verify(): Promise<AgentRegistrationStatus> {
    const session = this.agentSession.getStatus();
    const verifiedAt = this.now().toISOString();
    if (!session.ready || !session.agentDid) return this.status(null, 'UNAVAILABLE', null, null, verifiedAt, []);

    const agentDid = session.agentDid;
    let uri: string;
    try {
      setEnvironment(this.network);
      uri = new URL(`/api/agent-card/${encodeURIComponent(agentDid)}`, getNodeUrl()).toString();
    } catch {
      return this.status(agentDid, 'UNAVAILABLE', null, null, verifiedAt, []);
    }

    let response: Response;
    try {
      response = await this.fetcher(uri, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(5_000),
      });
    } catch {
      return this.status(agentDid, 'UNAVAILABLE', uri, null, verifiedAt, []);
    }

    if (response.status === 404) return this.status(agentDid, 'NOT_REGISTERED', uri, null, verifiedAt, []);
    if (!response.ok) return this.status(agentDid, 'UNAVAILABLE', uri, null, verifiedAt, []);

    const raw = await response.text();
    if (!raw || Buffer.byteLength(raw, 'utf8') >= MAX_AGENT_CARD_BYTES) {
      return this.status(agentDid, 'MISMATCH', uri, raw ? sha256(raw) : null, verifiedAt, []);
    }

    const cardHash = sha256(raw);
    try {
      const parsed = JSON.parse(raw) as unknown;
      const services = isRecord(parsed) ? servicesFrom(parsed) : [];
      assertAgentCardMatches(parsed, agentDid);
      return this.status(agentDid, 'REGISTERED', uri, cardHash, verifiedAt, services);
    } catch {
      let services: string[] = [];
      try {
        const parsed = JSON.parse(raw) as unknown;
        if (isRecord(parsed)) services = servicesFrom(parsed);
      } catch { /* malformed public card remains MISMATCH */ }
      return this.status(agentDid, 'MISMATCH', uri, cardHash, verifiedAt, services);
    }
  }

  private status(
    agentDid: string | null,
    agentRegistrationState: AgentRegistrationState,
    agentCardUri: string | null,
    agentCardSha256: string | null,
    agentCardVerifiedAt: string,
    agentCardServices: readonly string[],
  ): AgentRegistrationStatus {
    return { agentDid, agentRegistrationState, agentCardUri, agentCardSha256, agentCardVerifiedAt, agentCardServices };
  }
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
