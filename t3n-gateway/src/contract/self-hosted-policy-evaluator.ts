import type { PolicyEvaluationInput, PolicyEvaluator } from './policy-evaluator.js';
import { isPolicyDecision, type PolicyDecision } from './privacy-guard-contract.js';

export interface GuardRuntimeConfig {
  readonly url: string;
  readonly token: string;
  readonly agentId: string;
  readonly timeoutMs: number;
}

/**
 * Runs evaluate-action on the self-hosted guard-runtime instead of the T3N contract. The request keeps the
 * contract's wire format; agent_did is always the caller id the runtime authenticates this gateway as, so a
 * client-supplied agent_did can never reach the policy.
 */
export class SelfHostedPolicyEvaluator implements PolicyEvaluator {
  readonly runtime = 'selfhosted' as const;
  private readonly endpoint: string;

  constructor(
    private readonly config: GuardRuntimeConfig,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {
    this.endpoint = `${config.url.replace(/\/+$/, '')}/v1/functions/evaluate-action`;
  }

  get agentId(): string {
    return this.config.agentId;
  }

  async evaluate(request: PolicyEvaluationInput): Promise<PolicyDecision> {
    const response = await this.fetchImpl(this.endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.config.token}`,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ...request, private_refs: request.private_refs ?? [], agent_did: this.config.agentId }),
      redirect: 'error',
      signal: AbortSignal.timeout(this.config.timeoutMs),
    });
    if (!response.ok) throw new Error(`Guard runtime evaluate-action returned HTTP ${response.status}`);
    const result: unknown = await response.json();
    if (!isPolicyDecision(result)) throw new Error('Guard runtime returned an invalid policy decision');
    return result;
  }
}
