import { getContractVersion, getNodeUrl } from '@terminal3/t3n-sdk';
import type { AgentSession } from '../agent/agent-session.js';
import type { ExecutorSession } from '../agent/executor-session.js';
import type { GatewayConfig } from '../config/env.js';
import type { ActivityLogService, ActivityReference } from '../t3n/activity-log-service.js';
import type { T3nSession } from '../t3n/session.js';

export type PolicyDecisionType = 'ALLOW' | 'REDACT' | 'DENY';

interface ActivityAnnotated {
  readonly activity_sequence?: number;
  readonly activity_hash?: string;
}

export interface PolicyEvaluationRequest {
  readonly request_id: string;
  readonly agent_did: string;
  readonly action: string;
  readonly resource: string;
  readonly purpose: string;
  readonly host?: string;
  readonly fields: string[];
  readonly private_refs?: string[];
}

export interface PolicyDecision extends ActivityAnnotated {
  readonly request_id: string;
  readonly decision: PolicyDecisionType;
  readonly reason_code: string;
  readonly reason: string;
  readonly allowed_fields: string[];
  readonly redacted_fields: string[];
  readonly allowed_private_refs: string[];
  readonly redacted_private_refs: string[];
  readonly policy_version: string | null;
  readonly policy_hash: string | null;
  readonly requires_human_authorization: boolean;
}

export interface RemediationExecutionRequest {
  readonly request_id: string;
  readonly action: string;
  readonly resource: string;
  readonly purpose: string;
  readonly approved_host: string;
  readonly fields: string[];
  readonly private_refs?: string[];
  readonly policy_version: string;
  readonly policy_hash: string;
}

export interface RemediationResult extends ActivityAnnotated {
  readonly request_id: string;
  readonly status: 'PENDING_VERIFICATION';
  readonly http_code: number;
  readonly operation_id?: string | null;
  readonly policy_version: string;
  readonly policy_hash: string;
}

export interface RemediationVerificationRequest {
  readonly request_id: string;
  readonly operation_id: string;
  readonly expected_state: 'REVOKED';
}

export interface RemediationVerificationResult extends ActivityAnnotated {
  readonly request_id: string;
  readonly status: 'VERIFIED' | 'UNVERIFIED';
  readonly observed_state?: string | null;
}

export interface ContractIdentity { readonly contractId: string; readonly contractVersion: string; }
export interface DelegatedExecutionRequest<TInput> { readonly contract_id: string; readonly contract_version: string; readonly function_name: string; readonly pii_did: string; readonly input: TInput; }

export function buildDelegatedExecutionRequest<TInput>(tenantDid: string, contractId: string, contractVersion: string, functionName: string, input: TInput): DelegatedExecutionRequest<TInput> {
  if (!tenantDid.startsWith('did:t3n:')) throw new Error('Authenticated tenant DID is required for delegated execution');
  return { contract_id: contractId, contract_version: contractVersion, function_name: functionName, pii_did: tenantDid, input };
}

function validPolicyMetadata(version: unknown, hash: unknown): boolean {
  return (version == null && hash == null)
    || (typeof version === 'string' && version.length > 0 && typeof hash === 'string' && /^[a-f0-9]{64}$/.test(hash));
}

function isDecision(value: unknown): value is PolicyDecision {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<PolicyDecision>;
  return typeof candidate.request_id === 'string'
    && (candidate.decision === 'ALLOW' || candidate.decision === 'REDACT' || candidate.decision === 'DENY')
    && typeof candidate.reason_code === 'string'
    && typeof candidate.reason === 'string'
    && Array.isArray(candidate.allowed_fields)
    && Array.isArray(candidate.redacted_fields)
    && Array.isArray(candidate.allowed_private_refs)
    && Array.isArray(candidate.redacted_private_refs)
    && validPolicyMetadata(candidate.policy_version, candidate.policy_hash)
    && typeof candidate.requires_human_authorization === 'boolean';
}

function isRemediation(value: unknown): value is RemediationResult {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<RemediationResult>;
  return typeof candidate.request_id === 'string'
    && candidate.status === 'PENDING_VERIFICATION'
    && typeof candidate.http_code === 'number'
    && typeof candidate.policy_version === 'string'
    && typeof candidate.policy_hash === 'string'
    && /^[a-f0-9]{64}$/.test(candidate.policy_hash);
}

function isVerification(value: unknown): value is RemediationVerificationResult {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<RemediationVerificationResult>;
  return typeof candidate.request_id === 'string'
    && (candidate.status === 'VERIFIED' || candidate.status === 'UNVERIFIED')
    && (candidate.observed_state == null || typeof candidate.observed_state === 'string');
}

function annotate<T extends object>(result: T, activity?: ActivityReference): T & ActivityAnnotated {
  return activity ? { ...result, activity_sequence: activity.sequence, activity_hash: activity.hash } : result;
}

export class PrivacyGuardContractService {
  constructor(
    private readonly config: GatewayConfig,
    private readonly tenantSession: T3nSession,
    private readonly agentSession: AgentSession,
    private readonly executorSession: ExecutorSession,
    private readonly activityLog?: ActivityLogService,
  ) {}

  async canonicalContractId(): Promise<string> {
    await this.tenantSession.connect();
    const tenantId = this.tenantSession.getTenantDid().slice('did:t3n:'.length);
    return `z:${tenantId}:${this.config.contractTail}`;
  }

  async protectedExecutorDid(): Promise<string> {
    await this.executorSession.connect();
    return this.executorSession.getExecutorDid();
  }

  private async currentVersion(contractId: string): Promise<string> { return getContractVersion(getNodeUrl(), contractId); }

  private async capture<T>(actorDid: string, contractId: string, functionName: string, operation: () => Promise<T>): Promise<{ result: T; activity?: ActivityReference }> {
    if (!this.activityLog) return { result: await operation() };
    return this.activityLog.capture({
      actorDid,
      onBehalfOfDid: this.tenantSession.getTenantDid(),
      contractId,
      function: functionName,
    }, operation);
  }

  async identity(): Promise<ContractIdentity> {
    const contractId = await this.canonicalContractId();
    return { contractId, contractVersion: await this.currentVersion(contractId) };
  }

  async evaluate(request: Omit<PolicyEvaluationRequest, 'agent_did'>): Promise<PolicyDecision> {
    await this.agentSession.connect();
    const contractId = await this.canonicalContractId();
    const contractVersion = await this.currentVersion(contractId);
    const agentDid = this.agentSession.getAgentDid();
    const captured = await this.capture(agentDid, contractId, 'evaluate-action', () => this.agentSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
      this.tenantSession.getTenantDid(), contractId, contractVersion, 'evaluate-action',
      { ...request, private_refs: request.private_refs ?? [], agent_did: agentDid },
    )));
    if (!isDecision(captured.result)) throw new Error('T3N contract returned an invalid policy decision');
    return annotate(captured.result, captured.activity);
  }

  async remediate(request: RemediationExecutionRequest, authorizedExecutorDid: string): Promise<RemediationResult> {
    await Promise.all([this.agentSession.connect(), this.executorSession.connect()]);
    const executorDid = this.executorSession.getExecutorDid();
    if (authorizedExecutorDid !== executorDid) throw new Error('CAPABILITY_EXECUTOR_MISMATCH');
    const contractId = await this.canonicalContractId();
    const contractVersion = await this.currentVersion(contractId);
    const proposalAgentDid = this.agentSession.getAgentDid();
    const captured = await this.capture(executorDid, contractId, 'execute-remediation', () => this.executorSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
      this.tenantSession.getTenantDid(), contractId, contractVersion, 'execute-remediation',
      { ...request, private_refs: request.private_refs ?? [], agent_did: proposalAgentDid },
    )));
    if (!isRemediation(captured.result)) throw new Error('T3N contract returned an invalid remediation result');
    if (captured.result.policy_version !== request.policy_version || captured.result.policy_hash !== request.policy_hash) {
      throw new Error('T3N remediation policy metadata does not match the approved decision');
    }
    return annotate(captured.result, captured.activity);
  }

  async verifyRemediation(request: RemediationVerificationRequest): Promise<RemediationVerificationResult> {
    await this.executorSession.connect();
    const contractId = await this.canonicalContractId();
    const contractVersion = await this.currentVersion(contractId);
    const executorDid = this.executorSession.getExecutorDid();
    const captured = await this.capture(executorDid, contractId, 'verify-remediation', () => this.executorSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
      this.tenantSession.getTenantDid(), contractId, contractVersion, 'verify-remediation', request,
    )));
    if (!isVerification(captured.result)) throw new Error('T3N contract returned an invalid remediation verification result');
    return annotate(captured.result, captured.activity);
  }
}
