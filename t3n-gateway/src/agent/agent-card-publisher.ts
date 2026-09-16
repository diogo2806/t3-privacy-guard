import { createOrgDataClientFromSession, getNodeUrl } from '@terminal3/t3n-sdk';
import { sanitizeError } from '../security/sanitize.js';

export interface AgentCardPublicationRequest {
  readonly ownerDid: string;
  readonly agentDid: string;
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

export async function publishAgentCardToOrganization(
  request: AgentCardPublicationRequest,
  dependencies: AgentCardPublicationDependencies = DEFAULT_DEPENDENCIES,
): Promise<void> {
  try {
    const orgData = dependencies.createOrgDataClientFromSession(request.adminClient, dependencies.getNodeUrl());
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
