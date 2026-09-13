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
export type EffectiveDelegationState = 'ACTIVE' | 'INCOMPLETE' | 'UNKNOWN';
export interface DelegationStatus {
  readonly memberState: DelegationState;
  readonly effectiveState: EffectiveDelegationState;
  readonly functions: string[];
  readonly scopes: string[];
  readonly allowedHosts: string[];
  readonly satisfied: string[];
  readonly missing: string[];
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

function delegationLabels(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const labels = value.flatMap((entry) => {
    if (typeof entry === 'string') return [entry];
    if (!entry || typeof entry !== 'object') return [];
    const object = entry as Record<string, unknown>;
    for (const key of ['type', 'kind', 'source', 'edge']) {
      if (typeof object[key] === 'string') return [object[key] as string];
    }
    return [];
  });
  return [...new Set(labels.map((label) => label.trim()).filter(Boolean))].slice(0, 16);
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
    if (!contractId.trim()) throw new Error('contractId is required');
    await this.ensureSessions();
    const policy = await this.tenantSession.getClient().getMemberDelegation();
    const grant = this.findAgentGrant(policy, contractId);
    if (!grant) return this.statusWithoutEffectiveAccess('NOT_GRANTED');

    const functions = asStrings(grant.functions);
    const scopes = asStrings(grant.scopes);
    const allowedHosts = asStrings(grant.allowed_hosts);
    if (functions.length === 0 || scopes.length === 0) {
      return { memberState: 'UNKNOWN', effectiveState: 'UNKNOWN', functions, scopes, allowedHosts, satisfied: [], missing: [] };
    }

    const memberState = interpretDelegationWindow(grant.window, Math.floor(Date.now() / 1000));
    if (memberState !== 'ACTIVE') {
      return {
        memberState,
        effectiveState: memberState === 'UNKNOWN' ? 'UNKNOWN' : 'INCOMPLETE',
        functions,
        scopes,
        allowedHosts,
        satisfied: [],
        missing: [],
      };
    }

    try {
      const verdict = await this.agentSession.getClient().checkDelegation({
        contract: contractId,
        pii_did: this.tenantSession.getTenantDid(),
        functions,
        scopes,
      });
      if (!verdict || typeof verdict.authorised !== 'boolean') {
        return { memberState, effectiveState: 'UNKNOWN', functions, scopes, allowedHosts, satisfied: [], missing: [] };
      }
      return {
        memberState,
        effectiveState: verdict.authorised ? 'ACTIVE' : 'INCOMPLETE',
        functions,
        scopes,
        allowedHosts,
        satisfied: delegationLabels(verdict.satisfied),
        missing: delegationLabels(verdict.missing),
      };
    } catch {
      return { memberState, effectiveState: 'UNKNOWN', functions, scopes, allowedHosts, satisfied: [], missing: [] };
    }
  }

  private statusWithoutEffectiveAccess(memberState: DelegationState): DelegationStatus {
    return {
      memberState,
      effectiveState: memberState === 'UNKNOWN' ? 'UNKNOWN' : 'INCOMPLETE',
      functions: [],
      scopes: [],
      allowedHosts: [],
      satisfied: [],
      missing: [],
    };
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
