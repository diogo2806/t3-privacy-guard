import { ArrowRight, BadgeCheck, BrainCircuit, ServerCog, ShieldCheck, UserCheck } from 'lucide-react';
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
  icon: typeof BrainCircuit;
}

function t3nReady(status: SystemStatus | null): boolean {
  return Boolean(
    status?.gatewayReachable
      && status.tenantAuthenticated
      && status.agentAuthenticated
      && status.contractResolved
      && status.delegationState === 'ACTIVE',
  );
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
  if (execution?.state === 'PENDING_VERIFICATION' || execution?.state === 'COMPLETED') { executionState = 'ACCEPTED'; executionTone = 'success'; }
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
      detail: proposalReceived ? 'The model proposed an action. It did not authorize it.' : 'Waiting for an agent proposal.',
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
      detail: humanState === 'AUTHORIZED' ? 'Business authorization is recorded.' : humanState === 'REQUIRED' ? 'A human must authorize before protected execution.' : 'Human authorization applies only after an ALLOW decision.',
      tone: humanTone,
      icon: UserCheck,
    },
    {
      label: 'Protected execution',
      state: executionState,
      detail: executionState === 'NOT STARTED' ? 'No protected side effect is claimed.' : executionState === 'EXECUTING' ? 'Execution has been durably claimed and is in progress.' : executionState === 'ACCEPTED' ? 'The external action was accepted; acceptance is not completion.' : executionState === 'UNVERIFIED' ? 'The external outcome is ambiguous and will not be reported as completed.' : 'Execution failed without verified completion.',
      tone: executionTone,
      icon: ServerCog,
    },
    {
      label: 'Independent verification',
      state: verificationState,
      detail: verificationState === 'VERIFIED' ? 'Independent read-back confirmed the expected external state.' : verificationState === 'PENDING' ? 'Completion is waiting for independent read-back.' : verificationState === 'UNVERIFIED' ? 'Independent verification did not prove completion.' : 'No verified completion is claimed yet.',
      tone: verificationTone,
      icon: BadgeCheck,
    },
  ];
}

function resultMessage(
  decision: PolicyDecision | null,
  selectedAction: ActionProposal | null,
  execution: RemediationExecution | null,
  ready: boolean,
  statusLoading: boolean,
  proposalReceived: boolean,
): string {
  if (!statusLoading && !ready) return 'T3N controls are unavailable or incomplete. Policy decisions and protected execution cannot be proven until live status recovers.';
  if (!proposalReceived) return 'Start with a prompt. The AI may propose an action, but it has no authority to execute it.';
  if (!decision) return 'AI proposal received. T3N policy has not produced a decision yet.';
  if (decision.decision === 'DENY') return 'Policy blocked the proposal before protected egress. No execution is claimed.';
  if (decision.decision === 'REDACT') return 'Policy requires data minimization before the action may continue. No execution is claimed.';
  if (!isHumanAuthorized(selectedAction)) return 'Policy allowed the proposal, but protected execution is blocked until a human authorizes it.';
  if (!execution) return 'Human authorization is recorded. No protected execution has been claimed yet.';
  if (execution.state === 'EXECUTING') return 'Protected execution is in progress. Completion is not claimed.';
  if (execution.state === 'PENDING_VERIFICATION') return 'The external service accepted the action. Completion is pending independent verification.';
  if (execution.state === 'UNVERIFIED') return 'The external outcome is unverified. The system does not claim completion.';
  if (execution.state === 'FAILED') return 'Protected execution failed. No verified completion is claimed.';
  return 'External state was independently verified. The remediation is COMPLETED.';
}

export function TrustFlowSummary({ agentAnalysis, decision, selectedAction, remediationExecution, systemStatus, statusLoading }: Props) {
  const steps = trustSteps(agentAnalysis, decision, selectedAction, remediationExecution);
  const ready = t3nReady(systemStatus);
  const proposalReceived = Boolean(agentAnalysis || selectedAction);

  return (
    <section className="trust-flow card" aria-labelledby="trust-flow-title">
      <div className="trust-flow-heading">
        <div>
          <p className="eyebrow">Trust flow</p>
          <h2 id="trust-flow-title">AI proposes. Independent controls decide what happens next.</h2>
        </div>
        <span className={`trust-readiness ${statusLoading ? 'trust-readiness-pending' : ready ? 'trust-readiness-ready' : 'trust-readiness-unavailable'}`}>
          {statusLoading ? 'Checking T3N' : ready ? 'T3N controls ready' : 'T3N controls unavailable'}
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

      <p className="trust-result" aria-live="polite"><strong>Result:</strong> {resultMessage(decision, selectedAction, remediationExecution, ready, statusLoading, proposalReceived)}</p>
    </section>
  );
}
