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

function normalizeWriter(value: unknown): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error('T3N agent-cards writer list is invalid');
  }
  return value.trim();
}

function mergedWriters(existing: readonly string[], adminDid: string): string[] {
  const writers: string[] = [];
  const seen = new Set<string>();

  for (const rawWriter of existing) {
    const writer = normalizeWriter(rawWriter);
    if (!seen.has(writer)) {
      seen.add(writer);
      writers.push(writer);
    }
  }

  const canonicalAdminDid = normalizeWriter(adminDid);
  if (!seen.has(canonicalAdminDid)) writers.push(canonicalAdminDid);
  return writers;
}

function writerListsEqual(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  return left.every((value, index) => normalizeWriter(value) === right[index]);
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function isOrgPolicyNotInitialised(error: unknown): boolean {
  const message = errorMessage(error).toLowerCase();
  return message.includes('orgpolicynotinitialised') || message.includes('org policy is not initialised');
}

function isOrganisationNotFound(error: unknown): boolean {
  const message = errorMessage(error).toLowerCase();
  return message.includes('organisationnotfound')
    || message.includes('organizationnotfound')
    || message.includes('organisation does not exist')
    || message.includes('organization does not exist');
}

function isConcurrentPolicyInitialization(error: unknown): boolean {
  const message = errorMessage(error).toLowerCase();
  return message.includes('already initialised')
    || message.includes('already initialized')
    || message.includes('already exists');
}

function assertPolicyReadBack(policy: unknown): void {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('T3N organization policy read-back is invalid after initialization');
  }
}

function organizationNotFoundError(ownerDid: string): Error {
  return new Error(
    `T3N_ORG_DID ${ownerDid} does not identify a provisioned T3N organization (OrganisationNotFound); configure the canonical Organization DID instead of the Tenant/Admin DID`,
  );
}

async function preflightOrganizationPolicy(
  orgData: ReturnType<typeof createOrgDataClientFromSession>,
  ownerDid: string,
  adminDid: string,
): Promise<void> {
  try {
    const policy = await orgData.policyGet({ orgDid: ownerDid });
    assertPolicyReadBack(policy);
    return;
  } catch (error) {
    if (isOrganisationNotFound(error)) throw organizationNotFoundError(ownerDid);
    if (!isOrgPolicyNotInitialised(error)) throw error;
  }

  try {
    await orgData.createPolicy({
      orgDid: ownerDid,
      initialAdminDid: adminDid,
    });
  } catch (error) {
    if (isOrganisationNotFound(error)) throw organizationNotFoundError(ownerDid);
    if (!isConcurrentPolicyInitialization(error)) throw error;
  }

  try {
    const policy = await orgData.policyGet({ orgDid: ownerDid });
    assertPolicyReadBack(policy);
  } catch (error) {
    if (isOrganisationNotFound(error)) throw organizationNotFoundError(ownerDid);
    if (isOrgPolicyNotInitialised(error)) {
      throw new Error(
        `T3N OrgPolicy for ${ownerDid} is still not initialised after the authorized bootstrap attempt; verify T3N_ORG_DID and Tenant/Admin organization authority`,
      );
    }
    throw error;
  }
}

export async function publishAgentCardToOrganization(
  request: AgentCardPublicationRequest,
  dependencies: AgentCardPublicationDependencies = DEFAULT_DEPENDENCIES,
): Promise<void> {
  try {
    const orgData = dependencies.createOrgDataClientFromSession(request.adminClient, dependencies.getNodeUrl());
    await preflightOrganizationPolicy(orgData, request.ownerDid, request.adminDid);

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
