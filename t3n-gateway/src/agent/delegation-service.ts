import type { T3nSession } from '../t3n/session.js';
import type { AgentSession } from './agent-session.js';

export interface DelegationGrantRequest {
  readonly contractId: string;
  readonly versionReq?: string;
  readonly functions: string[];
  readonly scopes: string[];
  readonly allowedHosts?: string[];
  readonly readScopes?: string[];
  readonly validFromSecs?: number;
  readonly validUntilSecs?: number;
}

export type DelegationState = 'ACTIVE' | 'REVOKED' | 'NOT_GRANTED' | 'UNKNOWN';

interface GrantRecord {
  grantee?: unknown;
  contract_id?: unknown;
  version_req?: unknown;
  functions?: unknown;
  scopes?: unknown;
  read_scopes?: unknown;
  allowed_hosts?: unknown;
  window?: { valid_from_secs?: unknown; valid_until_secs?: unknown };
}

function assertNonEmpty(values: string[], field: string): void {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => !value.trim())) {
    throw new Error(`${field} must contain at least one non-empty value`);
  }
}

function extractGrants(value: unknown, depth = 0): GrantRecord[] {
  if (depth > 4 || !value || typeof value !== 'object') return [];
  const object = value as Record<string, unknown>;
  if (Array.isArray(object.grants)) return object.grants.filter((item): item is GrantRecord => Boolean(item && typeof item === 'object'));
  for (const key of ['value', 'result', 'data', 'policy', 'delegation']) {
    const nested = extractGrants(object[key], depth + 1);
    if (nested.length > 0) return nested;
  }
  return [];
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

export class DelegationService {
  constructor(
    private readonly tenantSession: T3nSession,
    private readonly agentSession: AgentSession,
  ) {}

  async grant(request: DelegationGrantRequest): Promise<void> {
    if (!request.contractId.trim()) throw new Error('contractId is required');
    assertNonEmpty(request.functions, 'functions');
    assertNonEmpty(request.scopes, 'scopes');
    await this.ensureSessions();

    await this.tenantSession.getClient().updateMemberDelegation({
      grantee: this.agentSession.getAgentDid(),
      contract_id: request.contractId,
      version_req: request.versionReq,
      functions: request.functions,
      scopes: request.scopes,
      read_scopes: request.readScopes,
      allowed_hosts: request.allowedHosts,
      window: request.validFromSecs || request.validUntilSecs
        ? { valid_from_secs: request.validFromSecs, valid_until_secs: request.validUntilSecs }
        : undefined,
    });
  }

  async revoke(contractId: string): Promise<DelegationState> {
    if (!contractId.trim()) throw new Error('contractId is required');
    await this.ensureSessions();
    const policy = await this.tenantSession.getClient().getMemberDelegation();
    const grant = this.findAgentGrant(policy, contractId);
    if (!grant) return 'NOT_GRANTED';

    const functions = asStrings(grant.functions);
    const scopes = asStrings(grant.scopes);
    if (functions.length === 0 || scopes.length === 0) {
      throw new Error('Existing delegation cannot be safely revoked because its functions/scopes are unreadable');
    }

    const now = Math.floor(Date.now() / 1000);
    await this.tenantSession.getClient().updateMemberDelegation({
      grantee: this.agentSession.getAgentDid(),
      contract_id: contractId,
      version_req: typeof grant.version_req === 'string' ? grant.version_req : undefined,
      functions,
      scopes,
      read_scopes: asStrings(grant.read_scopes),
      allowed_hosts: asStrings(grant.allowed_hosts),
      window: { valid_until_secs: now - 1 },
    });
    return 'REVOKED';
  }

  async status(contractId: string): Promise<{ state: DelegationState; policy: unknown }> {
    await this.ensureSessions();
    const policy = await this.tenantSession.getClient().getMemberDelegation();
    const grant = this.findAgentGrant(policy, contractId);
    if (!grant) return { state: 'NOT_GRANTED', policy };

    const validUntil = typeof grant.window?.valid_until_secs === 'number' ? grant.window.valid_until_secs : null;
    const state: DelegationState = validUntil !== null && validUntil < Math.floor(Date.now() / 1000) ? 'REVOKED' : 'ACTIVE';
    return { state, policy };
  }

  private findAgentGrant(policy: unknown, contractId: string): GrantRecord | undefined {
    const agentDid = this.agentSession.getAgentDid();
    return extractGrants(policy).find(
      (grant) => grant.grantee === agentDid && grant.contract_id === contractId,
    );
  }

  private async ensureSessions(): Promise<void> {
    await this.tenantSession.connect();
    await this.agentSession.connect();
  }
}
