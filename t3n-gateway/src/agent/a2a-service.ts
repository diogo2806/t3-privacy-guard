import { randomUUID } from 'node:crypto';
import type { PrivacyGuardContractService } from '../contract/privacy-guard-contract.js';
import { SensitivePromptError } from '../security/prompt-privacy-guard.js';
import type { AgentSession } from './agent-session.js';
import type { AgentService } from './agent-service.js';
import { validateAgentProposal, type AgentProposal } from './proposal-schema.js';

export interface A2aEvaluationResult {
  readonly proposal: AgentProposal;
  readonly decision: 'ALLOW' | 'REDACT' | 'DENY';
  readonly reasonCode: string;
  readonly policyVersion: string | null;
  readonly policyHash: string | null;
  readonly agentDid: string;
}

export class A2aProviderUnavailableError extends Error {
  constructor() {
    super('A2A_PROVIDER_UNAVAILABLE');
    this.name = 'A2aProviderUnavailableError';
  }
}

export class A2aDecisionUnavailableError extends Error {
  constructor() {
    super('A2A_DECISION_UNAVAILABLE');
    this.name = 'A2aDecisionUnavailableError';
  }
}

export class A2aEvaluationService {
  constructor(
    private readonly agentService: AgentService,
    private readonly contractService: Pick<PrivacyGuardContractService, 'evaluate'>,
    private readonly agentSession: Pick<AgentSession, 'getAgentDid'>,
  ) {}

  async evaluate(prompt: string): Promise<A2aEvaluationResult> {
    let proposal: AgentProposal;
    try {
      const providerResult = await this.agentService.propose(prompt);
      proposal = validateAgentProposal(providerResult.proposal);
    } catch (error) {
      if (error instanceof SensitivePromptError) throw error;
      throw new A2aProviderUnavailableError();
    }

    try {
      const decision = await this.contractService.evaluate({
        request_id: randomUUID(),
        action: proposal.action,
        resource: proposal.resource,
        purpose: proposal.purpose,
        ...(proposal.host ? { host: proposal.host } : {}),
        fields: proposal.fields,
        private_refs: proposal.private_refs,
      });

      return {
        proposal,
        decision: decision.decision,
        reasonCode: decision.reason_code,
        policyVersion: decision.policy_version,
        policyHash: decision.policy_hash,
        agentDid: this.agentSession.getAgentDid(),
      };
    } catch {
      throw new A2aDecisionUnavailableError();
    }
  }
}
