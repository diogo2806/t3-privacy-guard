import { ArrowRight, BadgeCheck, BrainCircuit, ServerCog, ShieldCheck, UserCheck, type LucideIcon } from 'lucide-react';
import type {
  ActionProposal,
  AgentAnalysis,
  PolicyDecision,
  RemediationExecution,
  SystemStatus,
} from '../../services/privacyGuardApi';
import { Button } from '../ui/Button';

interface Props {
  agentAnalysis: AgentAnalysis | null;
  decision: PolicyDecision | null;
  selectedAction: ActionProposal | null;
  remediationExecution: RemediationExecution | null;
  systemStatus: SystemStatus | null;
  statusLoading: boolean;
  busy?: boolean;
  onRetryEvaluation?: () => void;
}

type StepTone = 'pending' | 'info' | 'success' | 'warning' | 'danger';
interface TrustStep { label: string; state: string; detail: string; tone: StepTone; icon: LucideIcon; }

function readinessState(status: SystemStatus | null, loading: boolean): { className: string; label: string } {
  if (loading) return { className: 'trust-readiness-pending', label: 'Checking T3N' };
  if (status?.protectedRemediationReady) return { className: 'trust-readiness-ready', label: 'T3N controls ready' };
  if (status?.evaluationReady) return { className: 'trust-readiness-pending', label: 'Evaluation ready · execution blocked' };
  if (status?.delegationMemberState === 'SCHEDULED' || status?.executorDelegationMemberState === 'SCHEDULED') return { className: 'trust-readiness-pending', label: 'Member grant scheduled' };
  if (status?.delegationEffectiveState === 'DENIED' || status?.executorDelegationEffectiveState === 'DENIED') return { className: 'trust-readiness-unavailable', label: 'Effective access denied' };
  if (status?.delegationEffectiveState === 'UNKNOWN' || status?.executorDelegationEffectiveState === 'UNKNOWN') return { className: 'trust-readiness-unavailable', label: 'Effective access unknown' };
  return { className: 'trust-readiness-unavailable', label: 'T3N controls unavailable' };
}

function isHumanAuthorized(action: ActionProposal | null): boolean {
  return action?.status === 'REMEDIATION_AUTHORIZED' || action?.status === 'REMEDIATED';
}

function trustSteps(agentAnalysis: AgentAnalysis | null, decision: PolicyDecision | null, selectedAction: ActionProposal | null, execution: RemediationExecution | null): TrustStep[] {
  const proposalReceived = Boolean(agentAnalysis || selectedAction);
  const authorized = isHumanAuthorized(selectedAction);
  const policyTone: StepTone = !decision ? 'pending' : decision.decision === 'ALLOW' ? 'success' : decision.decision === 'REDACT' ? 'warning' : 'danger';
  const humanState = decision?.decision === 'ALLOW' ? authorized ? 'AUTHORIZED' : 'REQUIRED' : 'NOT NEEDED YET';
  const humanTone: StepTone = humanState === 'AUTHORIZED' ? 'success' : humanState === 'REQUIRED' ? 'warning' : 'pending';

  let executionState = 'BLOCKED';
  let executionTone: StepTone = 'pending';
  if (decision?.decision === 'ALLOW' && authorized) executionState = 'READY';
  if (execution?.state === 'EXECUTING') { executionState = 'EXECUTING'; executionTone = 'info'; }
  if (execution?.state === 'PENDING_VERIFICATION') { executionState = 'ACCEPTED'; executionTone = 'warning'; }
  if (execution?.state === 'COMPLETED') { executionState = 'ACCEPTED'; executionTone = 'success'; }
  if (execution?.state === 'UNVERIFIED') { executionState = 'UNVERIFIED'; executionTone = 'warning'; }
  if (execution?.state === 'FAILED') { executionState = 'FAILED'; executionTone = 'danger'; }

  let verificationState = 'WAITING';
  let verificationTone: StepTone = 'pending';
  if (execution?.state === 'PENDING_VERIFICATION') { verificationState = 'PENDING'; verificationTone = 'warning'; }
  if (execution?.state === 'COMPLETED') { verificationState = 'VERIFIED'; verificationTone = 'success'; }
  if (execution?.state === 'UNVERIFIED' || execution?.state === 'FAILED') { verificationState = 'UNVERIFIED'; verificationTone = 'danger'; }

  return [
    { label: 'AI', state: proposalReceived ? 'RECEIVED' : 'WAITING', detail: proposalReceived ? 'A structured action proposal exists. The Proposal Agent can request policy evaluation but cannot execute protected actions.' : 'Waiting for an agent proposal.', tone: proposalReceived ? 'info' : 'pending', icon: BrainCircuit },
    { label: 'Policy', state: decision?.decision ?? (selectedAction?.status === 'PENDING' ? 'PENDING' : 'WAITING'), detail: !decision ? 'T3N policy has not produced a decision yet.' : decision.decision === 'ALLOW' ? 'Policy allows the proposal to continue; it does not execute automatically.' : decision.decision === 'REDACT' ? 'The proposal must be minimized before it may continue.' : 'Policy blocked the proposal before protected egress.', tone: policyTone, icon: ShieldCheck },
    { label: 'Human', state: humanState, detail: humanState === 'AUTHORIZED' ? 'Authorization is recorded and bound to the current Protected Executor DID.' : humanState === 'REQUIRED' ? 'A human must authorize before the Protected Executor may be invoked.' : 'Human authorization applies only after an ALLOW decision.', tone: humanTone, icon: UserCheck },
    { label: 'Execute', state: executionState, detail: executionState === 'BLOCKED' ? 'No protected side effect is available yet.' : executionState === 'READY' ? 'The authorized request may invoke the separate Protected Executor.' : executionState === 'EXECUTING' ? 'The Protected Executor durably claimed execution and it is in progress.' : executionState === 'ACCEPTED' ? 'The external action was accepted; acceptance is not completion.' : executionState === 'UNVERIFIED' ? 'The external outcome is ambiguous and is not reported as completed.' : 'Execution failed without verified completion.', tone: executionTone, icon: ServerCog },
    { label: 'Verify', state: verificationState, detail: verificationState === 'VERIFIED' ? 'Independent read-back confirmed the expected external state.' : verificationState === 'PENDING' ? 'Completion is waiting for independent read-back.' : verificationState === 'UNVERIFIED' ? 'Independent verification did not prove completion.' : 'No verified completion is claimed yet.', tone: verificationTone, icon: BadgeCheck },
  ];
}

function resultMessage(decision: PolicyDecision | null, selectedAction: ActionProposal | null, execution: RemediationExecution | null, statusLoading: boolean, proposalReceived: boolean, status: SystemStatus | null): string {
  if (!statusLoading && status?.delegationMemberState === 'SCHEDULED') return 'The Proposal Member grant is scheduled, so policy evaluation is not ready.';
  if (!statusLoading && status?.delegationEffectiveState === 'DENIED') return 'T3N denied the effective access required for evaluation. The system fails closed.';
  if (!statusLoading && status?.delegationEffectiveState === 'UNKNOWN') return 'Proposal effective T3N access could not be confirmed. The system fails closed.';
  if (!statusLoading && status?.evaluationReady && !status.protectedRemediationReady) {
    if (status.executorDelegationEffectiveState === 'DENIED') return 'Policy evaluation is ready, but T3N denied Protected Executor access. Execution remains blocked.';
    return 'Policy evaluation is ready, but Protected Executor access is not confirmed. Execution remains blocked.';
  }
  if (!statusLoading && !status?.evaluationReady) return 'T3N controls are unavailable or incomplete. A Member grant alone is never treated as authorization.';
  if (!proposalReceived) return 'Analyze a synthetic scenario. The AI can propose, but it cannot authorize or execute.';
  if (!decision) return selectedAction?.status === 'PENDING' ? 'The proposal is waiting for T3N policy evaluation.' : 'A proposal exists, but T3N policy has not produced a decision yet.';
  if (decision.decision === 'DENY') return 'Proposal blocked before protected egress. No execution is claimed.';
  if (decision.decision === 'REDACT') return 'Data minimization is required before the action may continue.';
  if (!isHumanAuthorized(selectedAction)) return 'Human authorization is the next required action before protected execution.';
  if (!execution) return 'Authorization is recorded. Protected execution has not started.';
  if (execution.state === 'EXECUTING') return 'Protected execution is in progress. Completion is not claimed.';
  if (execution.state === 'PENDING_VERIFICATION') return 'External execution was accepted. Independent verification is the next required action.';
  if (execution.state === 'UNVERIFIED') return 'The external outcome is unverified. The system does not claim completion.';
  if (execution.state === 'FAILED') return 'Protected execution failed. No verified completion is claimed.';
  return 'Independent read-back verified the external state. Remediation is COMPLETED.';
}

export function TrustFlowSummary({ agentAnalysis, decision, selectedAction, remediationExecution, systemStatus, statusLoading, busy = false, onRetryEvaluation }: Props) {
  const steps = trustSteps(agentAnalysis, decision, selectedAction, remediationExecution);
  const proposalReceived = Boolean(agentAnalysis || selectedAction);
  const readiness = readinessState(systemStatus, statusLoading);

  return (
    <section className="trust-flow card" aria-labelledby="trust-flow-title">
      <div className="trust-flow-heading">
        <div><p className="eyebrow">Trust flow</p><h2 id="trust-flow-title">Authority stays outside the model</h2></div>
        <span className={`trust-readiness ${readiness.className}`}>{readiness.label}</span>
      </div>
      <ol className="trust-flow-steps">
        {steps.map((step, index) => {
          const Icon = step.icon;
          const retryHere = step.label === 'Policy' && selectedAction?.status === 'PENDING' && onRetryEvaluation;
          return <li key={step.label} className={`trust-step trust-step-${step.tone}`}>
            <div className="trust-step-icon"><Icon aria-hidden="true" /></div>
            <div className="trust-step-copy">
              <span>{index + 1}. {step.label}</span>
              <strong>{step.state}</strong>
              <details className="trust-step-details"><summary>Why</summary><small>{step.detail}</small></details>
              {retryHere && <Button variant="secondary" onClick={onRetryEvaluation} disabled={busy}>Retry T3N evaluation</Button>}
            </div>
            {index < steps.length - 1 && <ArrowRight className="trust-step-arrow" aria-hidden="true" />}
          </li>;
        })}
      </ol>
      <div className="trust-result" aria-live="polite"><span>Current result</span><strong>{resultMessage(decision, selectedAction, remediationExecution, statusLoading, proposalReceived, systemStatus)}</strong></div>
    </section>
  );
}
