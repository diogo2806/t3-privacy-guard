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

export interface DelegationCheckRequirements {
  readonly functions: readonly string[];
  readonly scopes: readonly string[];
}

export const PROPOSAL_DELEGATION_REQUIREMENTS: DelegationCheckRequirements = {
  functions: ['evaluate-action'],
  scopes: ['incident_id', 'credential_id', 'reason'],
};

export const EXECUTOR_DELEGATION_REQUIREMENTS: DelegationCheckRequirements = {
  functions: ['execute-remediation', 'verify-remediation'],
  scopes: ['incident_id', 'credential_id', 'reason'],
};

export type DelegationState = 'ACTIVE' | 'SCHEDULED' | 'REVOKED' | 'NOT_GRANTED' | 'UNKNOWN';
export type EffectiveDelegationState = 'ACTIVE' | 'DENIED' | 'UNKNOWN';

export interface DelegationStatus {
  readonly memberState: DelegationState;
  readonly effectiveState: EffectiveDelegationState;
  readonly functions: string[];
  readonly scopes: string[];
  readonly allowedHosts: string[];
  readonly checkedFunctions: string[];
  readonly checkedScopes: string[];
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

function assertNonEmpty(values: readonly string[], field: string): void {
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

function interpretEffectiveResult(value: unknown): EffectiveDelegationState {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return 'UNKNOWN';
  const authorised = (value as Record<string, unknown>).authorised;
  if (authorised === true) return 'ACTIVE';
  if (authorised === false) return 'DENIED';
  return 'UNKNOWN';
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
  constructor(
    private readonly tenantSession: T3nSession,
    private readonly principalSession: AgentSession,
    private readonly requirements: DelegationCheckRequirements,
  ) {
    assertNonEmpty(requirements.functions, 'check functions');
    assertNonEmpty(requirements.scopes, 'check scopes');
  }

  async grant(request: DelegationGrantRequest): Promise<void> {
    if (!request.contractId.trim()) throw new Error('contractId is required');
    assertNonEmpty(request.functions, 'functions');
    assertNonEmpty(request.scopes, 'scopes');
    await this.ensureSessions();
    await this.tenantSession.getClient().updateMemberDelegation({
      grantee: this.principalSession.getAgentDid(), contract_id: request.contractId, version_req: request.versionReq,
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
    const grant = this.findPrincipalGrant(policy, contractId);
    if (!grant) return 'NOT_GRANTED';
    const functions = asStrings(grant.functions);
    const scopes = asStrings(grant.scopes);
    if (functions.length === 0 || scopes.length === 0) throw new Error('Existing delegation cannot be safely revoked because its functions/scopes are unreadable');
    const now = Math.floor(Date.now() / 1000);
    await this.tenantSession.getClient().updateMemberDelegation({
      grantee: this.principalSession.getAgentDid(), contract_id: contractId,
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
    const grant = this.findPrincipalGrant(policy, contractId);
    if (!grant) return this.statusWithoutEffectiveCheck('NOT_GRANTED');

    const functions = asStrings(grant.functions);
    const scopes = asStrings(grant.scopes);
    const allowedHosts = asStrings(grant.allowed_hosts);
    if (functions.length === 0 || scopes.length === 0) {
      return this.statusWithoutEffectiveCheck('UNKNOWN', functions, scopes, allowedHosts);
    }

    const memberState = interpretDelegationWindow(grant.window, Math.floor(Date.now() / 1000));
    if (memberState !== 'ACTIVE') {
      const effectiveState: EffectiveDelegationState = memberState === 'UNKNOWN' ? 'UNKNOWN' : 'DENIED';
      return {
        memberState,
        effectiveState,
        functions,
        scopes,
        allowedHosts,
        checkedFunctions: [],
        checkedScopes: [],
      };
    }

    const checkedFunctions = [...this.requirements.functions];
    const checkedScopes = [...this.requirements.scopes];
    try {
      const result: unknown = await this.principalSession.getClient().checkDelegation({
        contract: contractId,
        pii_did: this.tenantSession.getTenantDid(),
        functions: checkedFunctions,
        scopes: checkedScopes,
      });
      return {
        memberState,
        effectiveState: interpretEffectiveResult(result),
        functions,
        scopes,
        allowedHosts,
        checkedFunctions,
        checkedScopes,
      };
    } catch {
      return {
        memberState,
        effectiveState: 'UNKNOWN',
        functions,
        scopes,
        allowedHosts,
        checkedFunctions,
        checkedScopes,
      };
    }
  }

  private statusWithoutEffectiveCheck(
    memberState: DelegationState,
    functions: string[] = [],
    scopes: string[] = [],
    allowedHosts: string[] = [],
  ): DelegationStatus {
    return {
      memberState,
      effectiveState: memberState === 'UNKNOWN' ? 'UNKNOWN' : 'DENIED',
      functions,
      scopes,
      allowedHosts,
      checkedFunctions: [],
      checkedScopes: [],
    };
  }

  private findPrincipalGrant(policy: unknown, contractId: string): GrantRecord | undefined {
    const principalDid = this.principalSession.getAgentDid();
    return extractGrants(policy).find((grant) => grant.grantee === principalDid && grant.contract_id === contractId);
  }

  private async ensureSessions(): Promise<void> {
    await this.tenantSession.connect();
    await this.principalSession.connect();
  }
}
