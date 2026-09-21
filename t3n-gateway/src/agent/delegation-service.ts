import type { T3nSession } from '../t3n/session.js';
import type { AgentSession } from './agent-session.js';

export interface DelegationGrantRequest {
  readonly contractId: string;
  readonly versionReq?: string;
  readonly function: string;
  readonly scopes: string[];
  readonly allowedHosts?: string[];
  readonly validFromSecs?: number;
  readonly validUntilSecs?: number;
}

export interface DelegationFunctionRequirement {
  readonly function: string;
  readonly scopes: readonly string[];
}

export interface DelegationCheckRequirements {
  readonly grants: readonly DelegationFunctionRequirement[];
  readonly functions: readonly string[];
  readonly scopes: readonly string[];
}

function requirements(grants: readonly DelegationFunctionRequirement[]): DelegationCheckRequirements {
  const normalized = grants.map((grant) => Object.freeze({
    function: grant.function,
    scopes: Object.freeze([...grant.scopes]),
  }));
  return Object.freeze({
    grants: Object.freeze(normalized),
    functions: Object.freeze(normalized.map((grant) => grant.function)),
    scopes: Object.freeze([...new Set(normalized.flatMap((grant) => grant.scopes))]),
  });
}

export const PROPOSAL_DELEGATION_REQUIREMENTS: DelegationCheckRequirements = requirements([
  {
    function: 'evaluate-action',
    scopes: ['incident_id', 'credential_id', 'reason'],
  },
]);

export const EXECUTOR_DELEGATION_REQUIREMENTS: DelegationCheckRequirements = requirements([
  {
    function: 'execute-remediation',
    scopes: ['incident_id', 'credential_id', 'reason', 'verified_contacts.email.value'],
  },
  {
    function: 'verify-remediation',
    scopes: ['incident_id', 'credential_id', 'reason'],
  },
]);

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
  allowed_hosts?: unknown;
  window?: unknown;
}

interface ParsedScopes {
  readonly paths: string[];
  readonly valid: boolean;
}

function assertRestrictions(values: readonly string[], field: string): void {
  if (!Array.isArray(values) || values.length === 0 || values.some((value) => !value.trim())) {
    throw new Error(`${field} must contain at least one non-empty value`);
  }
  if (values.some((value) => value.trim() === '*')) {
    throw new Error(`${field} must not contain wildcard grants`);
  }
}

function extractGrants(value: unknown, depth = 0): GrantRecord[] {
  if (depth > 4 || !value || typeof value !== 'object') return [];
  const object = value as Record<string, unknown>;
  if (Array.isArray(object.grants)) {
    return object.grants.filter((item): item is GrantRecord => Boolean(item && typeof item === 'object'));
  }
  for (const key of ['value', 'result', 'data', 'policy', 'delegation']) {
    const nested = extractGrants(object[key], depth + 1);
    if (nested.length > 0) return nested;
  }
  return [];
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function parseScopes(value: unknown): ParsedScopes {
  if (!Array.isArray(value) || value.length === 0) return { paths: [], valid: false };
  if (value.every((item) => typeof item === 'string')) {
    const paths = (value as string[]).map((item) => item.trim());
    return { paths, valid: paths.every(Boolean) };
  }

  const paths: string[] = [];
  for (const item of value) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return { paths: [], valid: false };
    const scope = item as Record<string, unknown>;
    if (typeof scope.path !== 'string' || !scope.path.trim() || typeof scope.access !== 'string' || !scope.access.trim()) {
      return { paths: [], valid: false };
    }
    paths.push(scope.path.trim());
  }
  return { paths, valid: true };
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) return false;
  const expected = new Set(right);
  return left.every((value) => expected.has(value));
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

function aggregateMemberState(states: readonly DelegationState[]): DelegationState {
  if (states.includes('UNKNOWN')) return 'UNKNOWN';
  if (states.includes('NOT_GRANTED')) return 'NOT_GRANTED';
  if (states.includes('REVOKED')) return 'REVOKED';
  if (states.includes('SCHEDULED')) return 'SCHEDULED';
  return 'ACTIVE';
}

export class DelegationService {
  private readonly requirements: DelegationCheckRequirements;

  constructor(
    private readonly tenantSession: T3nSession,
    private readonly agentSession: AgentSession,
    required: DelegationCheckRequirements,
  ) {
    if (required.grants.length === 0) throw new Error('at least one function-scoped delegation requirement is required');
    const seenFunctions = new Set<string>();
    for (const grant of required.grants) {
      assertRestrictions([grant.function], 'check functions');
      assertRestrictions(grant.scopes, 'check scopes');
      if (!seenFunctions.add(grant.function)) throw new Error('duplicate function-scoped delegation requirement');
    }
    this.requirements = requirements(required.grants);
  }

  async grant(request: DelegationGrantRequest): Promise<void> {
    if (!request.contractId.trim()) throw new Error('contractId is required');
    assertRestrictions([request.function], 'functions');
    assertRestrictions(request.scopes, 'scopes');
    await this.ensureSessions();
    await this.tenantSession.getClient().updateMemberDelegation({
      grantee: this.agentSession.getAgentDid(),
      contract_id: request.contractId,
      version_req: request.versionReq,
      functions: [request.function],
      scopes: request.scopes,
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
    const grants = this.findAgentGrants(policy, contractId);
    if (grants.length === 0) return 'NOT_GRANTED';

    const now = Math.floor(Date.now() / 1000);
    for (const grant of grants) {
      const functions = asStrings(grant.functions).map((value) => value.trim()).filter(Boolean);
      const parsedScopes = parseScopes(grant.scopes);
      if (functions.length !== 1 || functions[0] === '*' || !parsedScopes.valid) {
        throw new Error('Existing delegation cannot be safely revoked because it is not a valid function-scoped grant');
      }
      await this.tenantSession.getClient().updateMemberDelegation({
        grantee: this.agentSession.getAgentDid(),
        contract_id: contractId,
        version_req: typeof grant.version_req === 'string' ? grant.version_req : undefined,
        functions: [functions[0]],
        scopes: parsedScopes.paths,
        allowed_hosts: asStrings(grant.allowed_hosts),
        window: { valid_until_secs: now - 1 },
      });
    }
    return 'REVOKED';
  }

  async status(contractId: string): Promise<DelegationStatus> {
    if (!contractId.trim()) throw new Error('contractId is required');
    await this.ensureSessions();
    const policy = await this.tenantSession.getClient().getMemberDelegation();
    const grants = this.findAgentGrants(policy, contractId);

    const functions = [...new Set(grants.flatMap((grant) => asStrings(grant.functions).map((value) => value.trim()).filter(Boolean)))];
    const parsedScopeEntries = grants.map((grant) => parseScopes(grant.scopes));
    const scopes = [...new Set(parsedScopeEntries.flatMap((entry) => entry.paths))];
    const allowedHosts = [...new Set(grants.flatMap((grant) => asStrings(grant.allowed_hosts)))];

    if (grants.length === 0) {
      return {
        memberState: 'NOT_GRANTED',
        effectiveState: 'DENIED',
        functions,
        scopes,
        allowedHosts,
        checkedFunctions: [],
        checkedScopes: [],
      };
    }

    const byFunction = new Map<string, GrantRecord>();
    const requiredFunctions = new Set(this.requirements.grants.map((grant) => grant.function));
    let malformed = false;
    grants.forEach((grant, index) => {
      const grantFunctions = asStrings(grant.functions).map((value) => value.trim()).filter(Boolean);
      const parsed = parsedScopeEntries[index];
      const functionName = grantFunctions[0];
      if (
        grantFunctions.length !== 1
        || !functionName
        || functionName === '*'
        || !requiredFunctions.has(functionName)
        || !parsed.valid
      ) {
        malformed = true;
        return;
      }
      if (byFunction.has(functionName)) {
        malformed = true;
        return;
      }
      byFunction.set(functionName, grant);
    });

    if (malformed) {
      return {
        memberState: 'UNKNOWN',
        effectiveState: 'UNKNOWN',
        functions,
        scopes,
        allowedHosts,
        checkedFunctions: [],
        checkedScopes: [],
      };
    }

    const memberStates: DelegationState[] = [];
    for (const required of this.requirements.grants) {
      const grant = byFunction.get(required.function);
      if (!grant) {
        memberStates.push('NOT_GRANTED');
        continue;
      }
      const parsed = parseScopes(grant.scopes);
      if (!parsed.valid || !sameSet(parsed.paths, required.scopes)) {
        memberStates.push('UNKNOWN');
        continue;
      }
      memberStates.push(interpretDelegationWindow(grant.window, Math.floor(Date.now() / 1000)));
    }

    const memberState = aggregateMemberState(memberStates);
    if (memberState !== 'ACTIVE') {
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

    const checkedFunctions: string[] = [];
    const checkedScopes: string[] = [];
    let effectiveState: EffectiveDelegationState = 'ACTIVE';
    for (const required of this.requirements.grants) {
      checkedFunctions.push(required.function);
      for (const scope of required.scopes) {
        if (!checkedScopes.includes(scope)) checkedScopes.push(scope);
      }
      const state = await this.checkEffectiveAccess(contractId, required.function, [...required.scopes]);
      if (state === 'DENIED') effectiveState = 'DENIED';
      else if (state === 'UNKNOWN' && effectiveState === 'ACTIVE') effectiveState = 'UNKNOWN';
    }

    return { memberState, effectiveState, functions, scopes, allowedHosts, checkedFunctions, checkedScopes };
  }

  private async checkEffectiveAccess(
    contractId: string,
    functionName: string,
    scopes: string[],
  ): Promise<EffectiveDelegationState> {
    try {
      const result = await this.agentSession.getClient().checkDelegation({
        contract: contractId,
        pii_did: this.tenantSession.getTenantDid(),
        functions: [functionName],
        scopes,
      }) as unknown;
      if (!result || typeof result !== 'object' || typeof (result as Record<string, unknown>).authorised !== 'boolean') {
        return 'UNKNOWN';
      }
      return (result as { authorised: boolean }).authorised ? 'ACTIVE' : 'DENIED';
    } catch {
      return 'UNKNOWN';
    }
  }

  private findAgentGrants(policy: unknown, contractId: string): GrantRecord[] {
    const agentDid = this.agentSession.getAgentDid();
    return extractGrants(policy).filter((grant) => grant.grantee === agentDid && grant.contract_id === contractId);
  }

  private async ensureSessions(): Promise<void> {
    await this.tenantSession.connect();
    await this.agentSession.connect();
  }
}
