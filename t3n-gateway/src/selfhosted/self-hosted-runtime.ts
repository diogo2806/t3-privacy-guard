import type { DelegationStatus } from '../agent/delegation-service.js';
import type { GuardRuntimeConfig } from '../config/env.js';
import {
  annotate,
  isPolicyDecision,
  isRemediationResult,
  isVerificationResult,
  type ContractIdentity,
  type PolicyDecision,
  type RemediationExecutionRequest,
  type RemediationResult,
  type RemediationVerificationRequest,
  type RemediationVerificationResult,
} from '../contract/contract-types.js';
import {
  evaluateEnterpriseIntegrationReadinessForHosts,
  unknownEnterpriseIntegrationReadiness,
  VERIFICATION_CONTRACTS,
  type EnterpriseIntegrationReadiness,
} from '../contract/enterprise-readiness-rules.js';
import type { PolicyEvaluationInput, PolicyEvaluator } from '../contract/policy-evaluator.js';
import type { ActivityQuery, GuardRuntimeClient, RuntimeReadiness } from './guard-runtime-client.js';

export const SELF_HOSTED_NETWORK = 'selfhosted';

export type PrincipalKind = 'proposal' | 'executor';

export interface TenantStatusView {
  readonly connected: boolean;
  readonly ready: boolean;
  readonly tenantDid: string | null;
  readonly network: typeof SELF_HOSTED_NETWORK;
}

export interface PrincipalStatusView {
  readonly configured: boolean;
  readonly connected: boolean;
  readonly ready: boolean;
  readonly agentDid?: string | null;
  readonly executorDid?: string | null;
  readonly network: typeof SELF_HOSTED_NETWORK;
}

const REQUIRED_FUNCTIONS: Record<PrincipalKind, readonly string[]> = {
  proposal: ['evaluate-action'],
  executor: ['execute-remediation', 'verify-remediation'],
};

/**
 * Everything the T3N sessions, contract service and control-plane services answered, answered by guard-runtime.
 * The proposal agent and the protected executor keep separate tokens, exactly as they kept separate T3N keys.
 */
export class SelfHostedRuntime implements PolicyEvaluator {
  readonly runtime = 'selfhosted' as const;

  constructor(
    private readonly client: GuardRuntimeClient,
    private readonly config: GuardRuntimeConfig,
  ) {}

  get proposalAgentId(): string {
    return this.config.proposalAgentId;
  }

  get executorId(): string {
    return this.config.executorId;
  }

  async identity(): Promise<ContractIdentity> {
    const readiness = await this.client.readiness(this.config.executorToken);
    return { contractId: readiness.contract_id, contractVersion: readiness.contract_version };
  }

  async evaluate(request: PolicyEvaluationInput): Promise<PolicyDecision> {
    const result = await this.client.invoke('evaluate-action', this.config.proposalToken, {
      ...request,
      private_refs: request.private_refs ?? [],
      agent_did: this.config.proposalAgentId,
    });
    if (!isPolicyDecision(result.body)) throw new Error('Guard runtime returned an invalid policy decision');
    return annotate(result.body, result.activity);
  }

  async remediate(request: RemediationExecutionRequest, authorizedExecutorDid: string): Promise<RemediationResult> {
    const executorId = this.config.executorId;
    if (authorizedExecutorDid !== executorId || (request.executor_did && request.executor_did !== executorId)) {
      throw new Error('CAPABILITY_EXECUTOR_MISMATCH');
    }
    const result = await this.client.invoke('execute-remediation', this.config.executorToken, {
      ...request,
      incident_id: request.incident_id ?? request.request_id,
      action_id: request.action_id ?? request.request_id,
      decision_id: request.decision_id ?? request.request_id,
      executor_did: executorId,
      authorization_proof: request.authorization_proof ?? '',
      private_refs: request.private_refs ?? [],
      agent_did: this.config.proposalAgentId,
    });
    if (!isRemediationResult(result.body)) throw new Error('Guard runtime returned an invalid remediation result');
    if (result.body.policy_version !== request.policy_version || result.body.policy_hash !== request.policy_hash) {
      throw new Error('Guard runtime remediation policy metadata does not match the approved decision');
    }
    return annotate(result.body, result.activity);
  }

  async verifyRemediation(request: RemediationVerificationRequest): Promise<RemediationVerificationResult> {
    if (!request.action && request.expected_state !== 'REVOKED') {
      throw new Error('Verification action is required for non-revocation states');
    }
    const closedRequest = request.action ? request : { ...request, action: 'revoke-credential' as const };
    const result = await this.client.invoke('verify-remediation', this.config.executorToken, closedRequest);
    if (!isVerificationResult(result.body)) throw new Error('Guard runtime returned an invalid remediation verification result');
    return annotate(result.body, result.activity);
  }

  async tenantStatus(): Promise<TenantStatusView> {
    try {
      const readiness = await this.client.readiness(this.config.executorToken);
      return { connected: true, ready: true, tenantDid: readiness.tenant_id, network: SELF_HOSTED_NETWORK };
    } catch {
      return { connected: false, ready: false, tenantDid: null, network: SELF_HOSTED_NETWORK };
    }
  }

  async principalStatus(kind: PrincipalKind): Promise<PrincipalStatusView> {
    const expectedId = kind === 'proposal' ? this.config.proposalAgentId : this.config.executorId;
    let connected = false;
    let ready = false;
    try {
      const caller = await this.client.caller(this.token(kind));
      connected = true;
      ready = caller?.id === expectedId;
    } catch {
      // unreachable runtime: not connected
    }
    const identity = ready ? expectedId : null;
    return {
      configured: true,
      connected,
      ready,
      ...(kind === 'proposal' ? { agentDid: identity } : { executorDid: identity }),
      network: SELF_HOSTED_NETWORK,
    };
  }

  /** Member grant = the runtime knows the caller; effective access = it holds every function this role needs. */
  async delegationStatus(kind: PrincipalKind, knownReadiness?: RuntimeReadiness): Promise<DelegationStatus> {
    const required = [...REQUIRED_FUNCTIONS[kind]];
    try {
      const caller = await this.client.caller(this.token(kind));
      const expectedId = kind === 'proposal' ? this.config.proposalAgentId : this.config.executorId;
      if (!caller || caller.id !== expectedId) {
        return delegation('NOT_GRANTED', 'DENIED', caller?.functions ?? [], [], required);
      }
      const effective = required.every((fn) => caller.functions.includes(fn)) ? 'ACTIVE' : 'DENIED';
      const allowedHosts = kind === 'executor' ? remediationHosts(knownReadiness ?? await this.client.readiness(this.config.executorToken)) : [];
      return delegation('ACTIVE', effective, caller.functions, allowedHosts, required);
    } catch {
      return delegation('UNKNOWN', 'UNKNOWN', [], [], required);
    }
  }

  async readiness(): Promise<EnterpriseIntegrationReadiness> {
    const checkedAt = new Date().toISOString();
    let readiness: RuntimeReadiness;
    try {
      readiness = await this.client.readiness(this.config.executorToken);
    } catch {
      return unknownEnterpriseIntegrationReadiness(checkedAt, 'TRUST_RUNTIME_UNAVAILABLE');
    }
    if (readiness.policy_state === 'UNAVAILABLE') return unknownEnterpriseIntegrationReadiness(checkedAt, 'POLICY_UNAVAILABLE');
    if (readiness.policy_state !== 'AVAILABLE' || !readiness.policy_document) return unknownEnterpriseIntegrationReadiness(checkedAt, 'POLICY_INVALID');
    if (!readiness.endpoint_configuration_valid) return unknownEnterpriseIntegrationReadiness(checkedAt, 'ENDPOINT_CONFIGURATION_INVALID');
    return evaluateEnterpriseIntegrationReadinessForHosts({
      executionHost: readiness.execution_host,
      verificationHost: readiness.verification_host,
      // Without a capability verification key nothing can execute, so it counts as missing credentials.
      credentialConfigured: readiness.credential_configured && readiness.verification_key_configured,
      policy: readiness.policy_document,
      executorDelegation: await this.delegationStatus('executor', readiness),
      checkedAt,
    });
  }

  async activity(query: ActivityQuery): Promise<unknown> {
    return this.client.activity(this.config.proposalToken, query);
  }

  private token(kind: PrincipalKind): string {
    return kind === 'proposal' ? this.config.proposalToken : this.config.executorToken;
  }
}

function delegation(
  memberState: DelegationStatus['memberState'],
  effectiveState: DelegationStatus['effectiveState'],
  functions: string[],
  allowedHosts: string[],
  checkedFunctions: string[],
): DelegationStatus {
  return { memberState, effectiveState, functions: [...functions].sort(), scopes: [], allowedHosts, checkedFunctions, checkedScopes: [] };
}

/** The runtime only egresses to hosts every executable action's policy allows (the T3N grant's allowed_hosts). */
function remediationHosts(readiness: RuntimeReadiness): string[] {
  const actions = readiness.policy_document?.actions ?? {};
  const rules = VERIFICATION_CONTRACTS.map(({ action }) => actions[action]).filter((rule) => rule != null);
  if (rules.length !== VERIFICATION_CONTRACTS.length) return [];
  const [first, ...rest] = rules.map((rule) => new Set(rule.allowed_hosts));
  return [...first].filter((host) => rest.every((hosts) => hosts.has(host))).sort();
}
