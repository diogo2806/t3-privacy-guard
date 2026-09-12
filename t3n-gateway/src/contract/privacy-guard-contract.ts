import { getContractVersion, getNodeUrl } from '@terminal3/t3n-sdk';
import type { AgentSession } from '../agent/agent-session.js';
import type { T3nSession } from '../t3n/session.js';
import type { GatewayConfig } from '../config/env.js';

export type PolicyDecisionType = 'ALLOW' | 'REDACT' | 'DENY';

export interface PolicyEvaluationRequest {
  readonly request_id: string;
  readonly agent_did: string;
  readonly action: string;
  readonly resource: string;
  readonly purpose: string;
  readonly host?: string;
  readonly fields: string[];
}

export interface PolicyDecision {
  readonly request_id: string;
  readonly decision: PolicyDecisionType;
  readonly reason_code: string;
  readonly reason: string;
  readonly allowed_fields: string[];
  readonly redacted_fields: string[];
}

function isDecision(value: unknown): value is PolicyDecision {
  if (!value || typeof value !== 'object') return false;
  const candidate = value as Partial<PolicyDecision>;
  return typeof candidate.request_id === 'string'
    && (candidate.decision === 'ALLOW' || candidate.decision === 'REDACT' || candidate.decision === 'DENY')
    && typeof candidate.reason_code === 'string'
    && typeof candidate.reason === 'string'
    && Array.isArray(candidate.allowed_fields)
    && Array.isArray(candidate.redacted_fields);
}

export class PrivacyGuardContractService {
  constructor(
    private readonly config: GatewayConfig,
    private readonly tenantSession: T3nSession,
    private readonly agentSession: AgentSession,
  ) {}

  async canonicalContractId(): Promise<string> {
    await this.tenantSession.connect();
    const tenantId = this.tenantSession.getTenantDid().slice('did:t3n:'.length);
    return `z:${tenantId}:${this.config.contractTail}`;
  }

  async evaluate(request: Omit<PolicyEvaluationRequest, 'agent_did'>): Promise<PolicyDecision> {
    await this.agentSession.connect();
    const contractId = await this.canonicalContractId();
    const contractVersion = await getContractVersion(getNodeUrl(), contractId);
    const result = await this.agentSession.getClient().executeAndDecode({
      contract_id: contractId,
      contract_version: contractVersion,
      function_name: 'evaluate-action',
      input: {
        ...request,
        agent_did: this.agentSession.getAgentDid(),
      },
    });

    if (!isDecision(result)) throw new Error('T3N contract returned an invalid policy decision');
    return result;
  }
}
