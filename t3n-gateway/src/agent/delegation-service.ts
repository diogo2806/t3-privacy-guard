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

export const PROPOSAL_DELEGATION_REQUIREMENTS: DelegationCheckRequirements = Object.freeze({
  functions: Object.freeze(['evaluate-action']),
  scopes: Object.freeze(['incident_id', 'credential_id', 'reason']),
});

export const EXECUTOR_DELEGATION_REQUIREMENTS: DelegationCheckRequirements = Object.freeze({
  functions: Object.freeze(['execute-remediation', 'verify-remediation']),
  scopes: Object.freeze(['incident_id', 'credential_id', 'reason']),
});

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

function assertRestrictions(values: readonly string[], field: string): void {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => !value.trim())) {
    throw new Error(`${field} must contain at least one non-empty value`);
  }
  if (values.some((value) => value.trim() === '*')) throw new Error(`${field} must not contain wildcard grants`);
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
  private readonly requirements: DelegationCheckRequirements;

  constructor(
    private readonly tenantSession: T3nSession,
    private readonly agentSession: AgentSession,
    requirements: DelegationCheckRequirements,
  ) {
    assertRestrictions(requirements.functions, 'check functions');
    assertRestrictions(requirements.scopes, 'check scopes');
    this.requirements = {
      functions: [...requirements.functions],
      scopes: [...requirements.scopes],
    };
  }

  async grant(request: DelegationGrantRequest): Promise<void> {
    if (!request.contractId.trim()) throw new Error('contractId is required');
    assertRestrictions(request.functions, 'functions');
    assertRestrictions(request.scopes, 'scopes');
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
    const functions = grant ? asStrings(grant.functions) : [];
    const scopes = grant ? asStrings(grant.scopes) : [];
    const allowedHosts = grant ? asStrings(grant.allowed_hosts) : [];
    let memberState: DelegationState;
    if (!grant) memberState = 'NOT_GRANTED';
    else if (functions.length === 0 || scopes.length === 0) memberState = 'UNKNOWN';
    else memberState = interpretDelegationWindow(grant.window, Math.floor(Date.now() / 1000));

    const checkedFunctions = [...this.requirements.functions];
    const checkedScopes = [...this.requirements.scopes];
    const effectiveState = await this.checkEffectiveAccess(contractId, memberState, checkedFunctions, checkedScopes);
    return { memberState, effectiveState, functions, scopes, allowedHosts, checkedFunctions, checkedScopes };
  }

  private async checkEffectiveAccess(
    contractId: string,
    memberState: DelegationState,
    functions: string[],
    scopes: string[],
  ): Promise<EffectiveDelegationState> {
    let verdict: EffectiveDelegationState;
    try {
      const result = await this.agentSession.getClient().checkDelegation({
        contract: contractId,
        pii_did: this.tenantSession.getTenantDid(),
        functions,
        scopes,
      }) as unknown;
      if (!result || typeof result !== 'object' || typeof (result as Record<string, unknown>).authorised !== 'boolean') return 'UNKNOWN';
      verdict = (result as { authorised: boolean }).authorised ? 'ACTIVE' : 'DENIED';
    } catch {
      return 'UNKNOWN';
    }

    if (memberState === 'ACTIVE') return verdict;
    if (verdict === 'DENIED') return 'DENIED';
    return memberState === 'UNKNOWN' ? 'UNKNOWN' : 'DENIED';
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
