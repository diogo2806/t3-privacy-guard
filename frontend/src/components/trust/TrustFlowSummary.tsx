import { ArrowRight, BadgeCheck, BrainCircuit, ServerCog, ShieldCheck, UserCheck, type LucideIcon } from 'lucide-react';
import type {
  ActionProposal,
  AgentAnalysis,
  PolicyDecision,
  RemediationExecution,
  SystemStatus,
} from '../../services/privacyGuardApi';

interface Props {
  agentAnalysis: AgentAnalysis | null;
  decision: PolicyDecision | null;
  selectedAction: ActionProposal | null;
  remediationExecution: RemediationExecution | null;
  systemStatus: SystemStatus | null;
  statusLoading: boolean;
}

type StepTone = 'pending' | 'info' | 'success' | 'warning' | 'danger';

interface TrustStep {
  label: string;
  state: string;
  detail: string;
  tone: StepTone;
  icon: LucideIcon;
}

function readinessState(status: SystemStatus | null, loading: boolean): { className: string; label: string } {
  if (loading) return { className: 'trust-readiness-pending', label: 'Checking T3N' };
  if (status?.protectedRemediationReady) return { className: 'trust-readiness-ready', label: 'T3N controls ready' };
  if (status?.delegationState === 'SCHEDULED' || status?.executorDelegationState === 'SCHEDULED') {
    return { className: 'trust-readiness-pending', label: 'Delegation scheduled' };
  }
  if (status?.evaluationReady) return { className: 'trust-readiness-unavailable', label: 'Evaluation ready · execution blocked' };
  return { className: 'trust-readiness-unavailable', label: 'T3N controls unavailable' };
}

function isHumanAuthorized(action: ActionProposal | null): boolean {
  return action?.status === 'REMEDIATION_AUTHORIZED' || action?.status === 'REMEDIATED';
}

function trustSteps(
  agentAnalysis: AgentAnalysis | null,
  decision: PolicyDecision | null,
  selectedAction: ActionProposal | null,
  execution: RemediationExecution | null,
): TrustStep[] {
  const proposalReceived = Boolean(agentAnalysis || selectedAction);
  const authorized = isHumanAuthorized(selectedAction);

  const policyTone: StepTone = !decision
    ? 'pending'
    : decision.decision === 'ALLOW'
      ? 'success'
      : decision.decision === 'REDACT'
        ? 'warning'
        : 'danger';

  const humanState = decision?.decision === 'ALLOW'
    ? authorized ? 'AUTHORIZED' : 'REQUIRED'
    : 'NOT REQUIRED YET';
  const humanTone: StepTone = humanState === 'AUTHORIZED' ? 'success' : humanState === 'REQUIRED' ? 'warning' : 'pending';

  let executionState = 'NOT STARTED';
  let executionTone: StepTone = 'pending';
  if (execution?.state === 'EXECUTING') { executionState = 'EXECUTING'; executionTone = 'info'; }
  if (execution?.state === 'PENDING_VERIFICATION') { executionState = 'ACCEPTED'; executionTone = 'warning'; }
  if (execution?.state === 'COMPLETED') { executionState = 'ACCEPTED'; executionTone = 'success'; }
  if (execution?.state === 'UNVERIFIED') { executionState = 'UNVERIFIED'; executionTone = 'warning'; }
  if (execution?.state === 'FAILED') { executionState = 'FAILED'; executionTone = 'danger'; }

  let verificationState = 'NOT STARTED';
  let verificationTone: StepTone = 'pending';
  if (execution?.state === 'PENDING_VERIFICATION') { verificationState = 'PENDING'; verificationTone = 'warning'; }
  if (execution?.state === 'COMPLETED') { verificationState = 'VERIFIED'; verificationTone = 'success'; }
  if (execution?.state === 'UNVERIFIED' || execution?.state === 'FAILED') { verificationState = 'UNVERIFIED'; verificationTone = 'danger'; }

  return [
    {
      label: 'AI proposal',
      state: proposalReceived ? 'RECEIVED' : 'WAITING',
      detail: proposalReceived ? 'A structured action proposal is available. The Proposal Agent can evaluate only when effective T3N access is confirmed and has no protected-execution grant.' : 'Waiting for an agent proposal.',
      tone: proposalReceived ? 'info' : 'pending',
      icon: BrainCircuit,
    },
    {
      label: 'Policy',
      state: decision?.decision ?? 'WAITING',
      detail: !decision ? 'T3N policy has not produced a decision yet.' : decision.decision === 'ALLOW' ? 'Policy allows the proposal to continue, not to execute automatically.' : decision.decision === 'REDACT' ? 'The proposal must be minimized before it may continue.' : 'Policy blocked the proposal before protected egress.',
      tone: policyTone,
      icon: ShieldCheck,
    },
    {
      label: 'Human authorization',
      state: humanState,
      detail: humanState === 'AUTHORIZED' ? 'Business authorization is recorded and bound to the current Protected Executor DID.' : humanState === 'REQUIRED' ? 'A human must authorize before the Protected Executor may be invoked.' : 'Human authorization applies only after an ALLOW decision.',
      tone: humanTone,
      icon: UserCheck,
    },
    {
      label: 'Protected execution',
      state: executionState,
      detail: executionState === 'NOT STARTED' ? 'No protected side effect is claimed. Execution requires independently confirmed effective T3N access for the Protected Executor.' : executionState === 'EXECUTING' ? 'The Protected Executor has durably claimed execution and it is in progress.' : executionState === 'ACCEPTED' ? 'The external action was accepted by the Protected Executor; acceptance is not completion.' : executionState === 'UNVERIFIED' ? 'The external outcome is ambiguous and will not be reported as completed.' : 'Execution failed without verified completion.',
      tone: executionTone,
      icon: ServerCog,
    },
    {
      label: 'Independent verification',
      state: verificationState,
      detail: verificationState === 'VERIFIED' ? 'The Protected Executor performed independent read-back and confirmed the expected external state.' : verificationState === 'PENDING' ? 'Completion is waiting for independent read-back.' : verificationState === 'UNVERIFIED' ? 'Independent verification did not prove completion.' : 'No verified completion is claimed yet.',
      tone: verificationTone,
      icon: BadgeCheck,
    },
  ];
}

function resultMessage(
  decision: PolicyDecision | null,
  selectedAction: ActionProposal | null,
  execution: RemediationExecution | null,
  statusLoading: boolean,
  proposalReceived: boolean,
  systemStatus: SystemStatus | null,
): string {
  if (!statusLoading && (systemStatus?.delegationState === 'SCHEDULED' || systemStatus?.executorDelegationState === 'SCHEDULED')) {
    return 'A T3N Member Delegation is scheduled, but its authorization window has not begun. The affected capability remains unavailable.';
  }
  if (!statusLoading && !systemStatus?.evaluationReady) {
    if (systemStatus?.delegationEffectiveState === 'DENIED') return 'Proposal Member Delegation exists, but effective T3N access was denied for the required evaluation function/scopes. Evaluation remains blocked.';
    return 'Proposal evaluation cannot be proven ready until effective T3N access is independently confirmed for the Proposal Agent.';
  }
  if (!proposalReceived) return 'Start with a prompt. The AI may propose an action, but the Proposal Agent has no authority to execute it.';
  if (!decision) return 'An action proposal is available. T3N policy has not produced a decision yet.';
  if (decision.decision === 'DENY') return 'Policy blocked the proposal before protected egress. No execution is claimed.';
  if (decision.decision === 'REDACT') return 'Policy requires data minimization before the action may continue. No execution is claimed.';
  if (!statusLoading && !systemStatus?.protectedRemediationReady) {
    if (systemStatus?.executorDelegationEffectiveState === 'DENIED') return 'Policy allowed the proposal, but effective T3N access was denied for the Protected Executor. Protected remediation remains blocked.';
    return 'Policy allowed the proposal, but Protected Executor effective T3N access is not confirmed. Protected remediation remains blocked.';
  }
  if (!isHumanAuthorized(selectedAction)) return 'Policy allowed the proposal, but the Protected Executor remains blocked until a human authorizes it.';
  if (!execution) return 'Human authorization is recorded and bound to the Protected Executor. No protected execution has been claimed yet.';
  if (execution.state === 'EXECUTING') return 'Protected execution is in progress. Completion is not claimed.';
  if (execution.state === 'PENDING_VERIFICATION') return 'The external service accepted the action. Completion is pending independent verification.';
  if (execution.state === 'UNVERIFIED') return 'The external outcome is unverified. The system does not claim completion.';
  if (execution.state === 'FAILED') return 'Protected execution failed. No verified completion is claimed.';
  return 'External state was independently verified. The remediation is COMPLETED.';
}

export function TrustFlowSummary({ agentAnalysis, decision, selectedAction, remediationExecution, systemStatus, statusLoading }: Props) {
  const steps = trustSteps(agentAnalysis, decision, selectedAction, remediationExecution);
  const proposalReceived = Boolean(agentAnalysis || selectedAction);
  const readiness = readinessState(systemStatus, statusLoading);

  return (
    <section className="trust-flow card" aria-labelledby="trust-flow-title">
      <div className="trust-flow-heading">
        <div>
          <p className="eyebrow">Trust flow</p>
          <h2 id="trust-flow-title">AI proposes. Humans authorize. A separate T3N executor performs protected actions.</h2>
        </div>
        <span className={`trust-readiness ${readiness.className}`}>
          {readiness.label}
        </span>
      </div>

      <ol className="trust-flow-steps">
        {steps.map((step, index) => {
          const Icon = step.icon;
          return (
            <li key={step.label} className={`trust-step trust-step-${step.tone}`}>
              <div className="trust-step-icon"><Icon aria-hidden="true" /></div>
              <div className="trust-step-copy">
                <span>{step.label}</span>
                <strong>{step.state}</strong>
                <small>{step.detail}</small>
              </div>
              {index < steps.length - 1 && <ArrowRight className="trust-step-arrow" aria-hidden="true" />}
            </li>
          );
        })}
      </ol>

      <p className="trust-result" aria-live="polite"><strong>Result:</strong> {resultMessage(decision, selectedAction, remediationExecution, statusLoading, proposalReceived, systemStatus)}</p>
    </section>
  );
}