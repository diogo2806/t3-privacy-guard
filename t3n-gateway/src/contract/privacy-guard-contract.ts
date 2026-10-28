import { getContractVersion, getNodeUrl } from '@terminal3/t3n-sdk';
import type { AgentSession } from '../agent/agent-session.js';
import type { ExecutorSession } from '../agent/executor-session.js';
import type { GatewayConfig } from '../config/env.js';
import { getFreshContractVersion } from './fresh-contract-version.js';
import type { PolicyEvaluator } from './policy-evaluator.js';
import type { ActivityLogService } from '../t3n/activity-log-service.js';
import type { T3nSession } from '../t3n/session.js';
import {
  annotate,
  isPolicyDecision,
  isRemediationResult,
  isVerificationResult,
  type ActivityReference,
  type ContractIdentity,
  type PolicyDecision,
  type PolicyEvaluationRequest,
  type RemediationExecutionRequest,
  type RemediationResult,
  type RemediationVerificationRequest,
  type RemediationVerificationResult,
} from './contract-types.js';

export * from './contract-types.js';

export interface DelegatedExecutionRequest<TInput> { readonly contract_id: string; readonly contract_version: string; readonly function_name: string; readonly pii_did: string; readonly input: TInput; }
export type ContractVersionLookup = (nodeUrl: string, contractId: string) => Promise<string>;

export function buildDelegatedExecutionRequest<TInput>(tenantDid: string, contractId: string, contractVersion: string, functionName: string, input: TInput): DelegatedExecutionRequest<TInput> {
  if (!tenantDid.startsWith('did:t3n:')) throw new Error('Authenticated tenant DID is required for delegated execution');
  return { contract_id: contractId, contract_version: contractVersion, function_name: functionName, pii_did: tenantDid, input };
}

export class PrivacyGuardContractService implements PolicyEvaluator {
  readonly runtime = 't3n' as const;

  constructor(
    private readonly config: GatewayConfig,
    private readonly tenantSession: T3nSession,
    private readonly agentSession: AgentSession,
    private readonly executorSession: ExecutorSession,
    private readonly activityLog?: ActivityLogService,
    private readonly freshVersionLookup: ContractVersionLookup = getFreshContractVersion,
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
    return { contractId, contractVersion: await this.freshVersionLookup(getNodeUrl(), contractId) };
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
    if (!isPolicyDecision(captured.result)) throw new Error('T3N contract returned an invalid policy decision');
    return annotate(captured.result, captured.activity);
  }

  async remediate(request: RemediationExecutionRequest, authorizedExecutorDid: string): Promise<RemediationResult> {
    await Promise.all([this.agentSession.connect(), this.executorSession.connect()]);
    const executorDid = this.executorSession.getExecutorDid();
    if (authorizedExecutorDid !== executorDid || (request.executor_did && request.executor_did !== executorDid)) {
      throw new Error('CAPABILITY_EXECUTOR_MISMATCH');
    }
    const contractId = await this.canonicalContractId();
    const contractVersion = await this.currentVersion(contractId);
    const proposalAgentDid = this.agentSession.getAgentDid();
    const delegatedInput = {
      ...request,
      incident_id: request.incident_id ?? request.request_id,
      action_id: request.action_id ?? request.request_id,
      decision_id: request.decision_id ?? request.request_id,
      executor_did: request.executor_did ?? executorDid,
      authorization_proof: request.authorization_proof ?? '',
      private_refs: request.private_refs ?? [],
      agent_did: proposalAgentDid,
    };
    const captured = await this.capture(executorDid, contractId, 'execute-remediation', () => this.executorSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
      this.tenantSession.getTenantDid(), contractId, contractVersion, 'execute-remediation', delegatedInput,
    )));
    if (!isRemediationResult(captured.result)) throw new Error('T3N contract returned an invalid remediation result');
    if (captured.result.policy_version !== request.policy_version || captured.result.policy_hash !== request.policy_hash) {
      throw new Error('T3N remediation policy metadata does not match the approved decision');
    }
    return annotate(captured.result, captured.activity);
  }

  async verifyRemediation(request: RemediationVerificationRequest): Promise<RemediationVerificationResult> {
    await this.executorSession.connect();
    if (!request.action && request.expected_state !== 'REVOKED') {
      throw new Error('Verification action is required for non-revocation states');
    }
    const closedRequest = request.action ? request : { ...request, action: 'revoke-credential' as const };
    const contractId = await this.canonicalContractId();
    const contractVersion = await this.currentVersion(contractId);
    const executorDid = this.executorSession.getExecutorDid();
    const captured = await this.capture(executorDid, contractId, 'verify-remediation', () => this.executorSession.getClient().executeAndDecode(buildDelegatedExecutionRequest(
      this.tenantSession.getTenantDid(), contractId, contractVersion, 'verify-remediation', closedRequest,
    )));
    if (!isVerificationResult(captured.result)) throw new Error('T3N contract returned an invalid remediation verification result');
    return annotate(captured.result, captured.activity);
  }
}
