import type { PolicyDecision, PolicyEvaluationRequest } from './privacy-guard-contract.js';

export type TrustRuntime = 't3n' | 'selfhosted';

/** Callers never choose the agent identity; each runtime binds it to the principal it authenticates. */
export type PolicyEvaluationInput = Omit<PolicyEvaluationRequest, 'agent_did'>;

/** Where evaluate-action runs: the T3N contract (PrivacyGuardContractService) or the self-hosted guard-runtime. */
export interface PolicyEvaluator {
  readonly runtime: TrustRuntime;
  evaluate(request: PolicyEvaluationInput): Promise<PolicyDecision>;
}

export function evaluationTraceStage(runtime: TrustRuntime): string {
  return runtime === 't3n' ? 'T3N_TEE_EVALUATION' : 'GUARD_RUNTIME_EVALUATION';
}
