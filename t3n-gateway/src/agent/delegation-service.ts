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

export type DelegationState = 'ACTIVE' | 'SCHEDULED' | 'REVOKED' | 'NOT_GRANTED' | 'UNKNOWN';
export interface DelegationStatus {
  readonly state: DelegationState;
  readonly functions: string[];
  readonly allowedHosts: string[];
  readonly policy: unknown;
}

interface GrantRecord {
  grantee?: unknown;
  contract_id?: unknown;
  version_req?: unknown;
  functions?: unknown;
  scopes?: unknown;
  read_scopes?: unknown;
  allowed_hosts?: unknown;
  window?: unknown;
}

function assertNonEmpty(values: string[], field: string): void {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => !value.trim())) throw new Error(`${field} must contain at least one non-empty value`);
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

function optionalFiniteNumber(object: Record<string, unknown>, key: string): number | null | undefined {
  if (!(key in object)) return undefined;
  const value = object[key];
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return value;
}

export function interpretDelegationWindow(window: unknown, nowSecs: number): DelegationState {
  if (window === undefined || window === null) return 'ACTIVE';
  if (!window || typeof window !== 'object' || Array.isArray(window)) return 'UNKNOWN';

  const object = window as Record<string, unknown>;
  const validFrom = optionalFiniteNumber(object, 'valid_from_secs');
  const validUntil = optionalFiniteNumber(object, 'valid_until_secs');
  if (validFrom === null || validUntil === null) return 'UNKNOWN';
  if (validFrom !== undefined && validUntil !== undefined && validFrom > validUntil) return 'UNKNOWN';
  if (validUntil !== undefined && validUntil < nowSecs) return 'REVOKED';
  if (validFrom !== undefined && validFrom > nowSecs) return 'SCHEDULED';
  return 'ACTIVE';
}

export class DelegationService {
  constructor(private readonly tenantSession: T3nSession, private readonly agentSession: AgentSession) {}

  async grant(request: DelegationGrantRequest): Promise<void> {
    if (!request.contractId.trim()) throw new Error('contractId is required');
    assertNonEmpty(request.functions, 'functions');
    assertNonEmpty(request.scopes, 'scopes');
    await this.ensureSessions();
    await this.tenantSession.getClient().updateMemberDelegation({
      grantee: this.agentSession.getAgentDid(), contract_id: request.contractId, version_req: request.versionReq,
      functions: request.functions, scopes: request.scopes, read_scopes: request.readScopes,
      allowed_hosts: request.allowedHosts,
      window: request.validFromSecs !== undefined || request.validUntilSecs !== undefined
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
    if (functions.length === 0 || scopes.length === 0) throw new Error('Existing delegation cannot be safely revoked because its functions/scopes are unreadable');
    const now = Math.floor(Date.now() / 1000);
    await this.tenantSession.getClient().updateMemberDelegation({
      grantee: this.agentSession.getAgentDid(), contract_id: contractId,
      version_req: typeof grant.version_req === 'string' ? grant.version_req : undefined,
      functions, scopes, read_scopes: asStrings(grant.read_scopes), allowed_hosts: asStrings(grant.allowed_hosts),
      window: { valid_until_secs: now - 1 },
    });
    return 'REVOKED';
  }

  async status(contractId: string): Promise<DelegationStatus> {
    await this.ensureSessions();
    const policy = await this.tenantSession.getClient().getMemberDelegation();
    const grant = this.findAgentGrant(policy, contractId);
    if (!grant) return { state: 'NOT_GRANTED', functions: [], allowedHosts: [], policy };
    const functions = asStrings(grant.functions);
    const scopes = asStrings(grant.scopes);
    const allowedHosts = asStrings(grant.allowed_hosts);
    if (functions.length === 0 || scopes.length === 0) return { state: 'UNKNOWN', functions, allowedHosts, policy };
    const state = interpretDelegationWindow(grant.window, Math.floor(Date.now() / 1000));
    return { state, functions, allowedHosts, policy };
  }

  private findAgentGrant(policy: unknown, contractId: string): GrantRecord | undefined {
    const agentDid = this.agentSession.getAgentDid();
    return extractGrants(policy).find((grant) => grant.grantee === agentDid && grant.contract_id === contractId);
  }

  private async ensureSessions(): Promise<void> {
    await this.tenantSession.connect();
    await this.agentSession.connect();
  }
}
