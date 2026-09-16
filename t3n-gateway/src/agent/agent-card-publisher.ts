import {
  AGENT_CARDS_SCOPE,
  createOrgDataClientFromSession,
  getNodeUrl,
} from '@terminal3/t3n-sdk';
import { sanitizeError } from '../security/sanitize.js';

export interface AgentCardPublicationRequest {
  readonly ownerDid: string;
  readonly agentDid: string;
  readonly adminDid: string;
  readonly card: string;
  readonly adminClient: Parameters<typeof createOrgDataClientFromSession>[0];
  readonly secrets?: readonly string[];
}

export interface AgentCardPublicationDependencies {
  readonly createOrgDataClientFromSession: typeof createOrgDataClientFromSession;
  readonly getNodeUrl: typeof getNodeUrl;
}

const DEFAULT_DEPENDENCIES: AgentCardPublicationDependencies = Object.freeze({
  createOrgDataClientFromSession,
  getNodeUrl,
});

function canonicalDid(value: string): string {
  return value.trim().toLowerCase();
}

function mergedWriters(existing: readonly string[], adminDid: string): string[] {
  const writers = new Map<string, string>();
  for (const writer of existing) {
    if (typeof writer !== 'string' || !writer.trim()) {
      throw new Error('T3N agent-cards writer list is invalid');
    }
    const key = canonicalDid(writer);
    if (!writers.has(key)) writers.set(key, writer);
  }
  const adminKey = canonicalDid(adminDid);
  if (!adminKey) throw new Error('Authenticated Tenant/Admin DID is required for Agent Card publication');
  if (!writers.has(adminKey)) writers.set(adminKey, adminDid);
  return [...writers.values()];
}

function writerListsEqual(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((value, index) => canonicalDid(value) === canonicalDid(right[index] ?? ''));
}

export async function publishAgentCardToOrganization(
  request: AgentCardPublicationRequest,
  dependencies: AgentCardPublicationDependencies = DEFAULT_DEPENDENCIES,
): Promise<void> {
  try {
    const orgData = dependencies.createOrgDataClientFromSession(request.adminClient, dependencies.getNodeUrl());
    const writerState = await orgData.writersGet({
      orgDid: request.ownerDid,
      scope: AGENT_CARDS_SCOPE,
    });
    if (!writerState || !Array.isArray(writerState.writers)) {
      throw new Error('T3N agent-cards writer response is invalid');
    }

    const writers = mergedWriters(writerState.writers, request.adminDid);
    if (!writerListsEqual(writerState.writers, writers)) {
      await orgData.setWriters({
        orgDid: request.ownerDid,
        scope: AGENT_CARDS_SCOPE,
        writers,
      });
    }

    await orgData.agentCardSet({
      ownerDid: request.ownerDid,
      agentDid: request.agentDid,
      card: request.card,
    });
    await orgData.agentCardPublish({
      ownerDid: request.ownerDid,
      agentDid: request.agentDid,
    });
  } catch (error) {
    const sanitized = sanitizeError(error, request.secrets);
    throw new Error(`T3N Agent Card publication failed (${sanitized.category}): ${sanitized.message}`);
  }
}
