import {
  ArrowRight,
  BadgeCheck,
  BrainCircuit,
  CircleAlert,
  FileCheck2,
  ServerCog,
  ShieldCheck,
  UserCheck,
  type LucideIcon,
} from 'lucide-react';
import type {
  ActionProposal,
  AgentAnalysis,
  BusinessImpact,
  PolicyDecision,
  RemediationExecution,
  SystemStatus,
} from '../../services/privacyGuardApi';
import { PrivacyGuardMark } from '../brand/PrivacyGuardMark';
import { formatObservedDuration } from '../business/BusinessOutcomeSummary';
import { ControlImpactSummary } from '../business/ControlImpactSummary';
import { ScreenManualDialog } from '../manual/ScreenManualDialog';
import type { EnterpriseScenarioDefinition } from '../scenarios/scenarioDefinitions';
import { Surface } from '../ui/Surface';

interface Props {
  scenario: EnterpriseScenarioDefinition | null;
  systemStatus: SystemStatus | null;
  statusLoading: boolean;
  agentAnalysis: AgentAnalysis | null;
  selectedAction: ActionProposal | null;
  decision: PolicyDecision | null;
  remediationExecution: RemediationExecution | null;
  businessImpact?: BusinessImpact | null;
  businessImpactLoading?: boolean;
  businessImpactError?: string | null;
}

type Tone = 'pending' | 'info' | 'success' | 'warning' | 'danger';

interface TrustStep {
  label: string;
  state: string;
  detail: string;
  tone: Tone;
  icon: LucideIcon;
}

const NOT_OBSERVED = 'NOT YET OBSERVED';

function elapsedMs(start?: string | null, end?: string | null): number | null {
  if (!start || !end) return null;
  const startMs = Date.parse(start);
  const endMs = Date.parse(end);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) return null;
  return endMs - startMs;
}

function isHumanAuthorized(action: ActionProposal | null): boolean {
  return action?.status === 'REMEDIATION_AUTHORIZED' || action?.status === 'REMEDIATED';
}

function readiness(status: SystemStatus | null, statusLoading: boolean) {
  if (statusLoading) return { label: 'CHECKING RUNTIME', tone: 'pending' as const };
  if (status?.protectedRemediationReady && status.enterpriseIntegrationReady) {
    return { label: 'GUARD RUNTIME LIVE / READY', tone: 'success' as const };
  }
  if (status) return { label: 'INCOMPLETE', tone: 'warning' as const };
  return { label: 'NOT READY', tone: 'danger' as const };
}

function observedOutcome(action: ActionProposal | null, decision: PolicyDecision | null, execution: RemediationExecution | null): string {
  if (execution?.state === 'COMPLETED') return action?.action === 'revoke-credential' ? 'VERIFIED EXTERNAL STATE: REVOKED' : 'VERIFIED EXTERNAL STATE';
  if (execution?.state === 'PENDING_VERIFICATION') return 'ACCEPTED / NOT VERIFIED';
  if (execution?.state === 'UNVERIFIED') return 'UNVERIFIED — COMPLETION NOT CLAIMED';
  if (execution?.state === 'FAILED') return 'FAILED — NO VERIFIED OUTCOME';
  if (execution?.state === 'EXECUTING') return 'PROTECTED EXECUTION IN PROGRESS';
  if (isHumanAuthorized(action)) return 'AUTHORIZED / NOT EXECUTED';
  if (decision?.decision === 'ALLOW') return 'HUMAN AUTHORIZATION REQUIRED';
  if (decision?.decision === 'REDACT') return 'MINIMIZATION REQUIRED';
  if (decision?.decision === 'DENY') return 'BLOCKED BEFORE PROTECTED EGRESS';
  return NOT_OBSERVED;
}

function trustPath(action: ActionProposal | null, decision: PolicyDecision | null, execution: RemediationExecution | null): TrustStep[] {
  const authorized = isHumanAuthorized(action);
  const proposalDetail = action
    ? `${action.action}${action.host ? ` → ${action.host}` : ' → no outbound host'}`
    : 'Waiting for agent analysis.';
  const policyTone: Tone = !decision ? 'pending' : decision.decision === 'ALLOW' ? 'success' : decision.decision === 'REDACT' ? 'warning' : 'danger';

  let humanState = 'WAITING';
  let humanTone: Tone = 'pending';
  if (decision?.decision === 'ALLOW') {
    humanState = authorized ? 'AUTHORIZED' : 'REQUIRED';
    humanTone = authorized ? 'success' : 'warning';
  } else if (decision) {
    humanState = 'NOT APPLICABLE';
  }

  let executorState = decision ? 'NOT EXECUTED' : 'WAITING';
  let executorTone: Tone = 'pending';
  if (decision?.decision === 'ALLOW' && authorized) executorState = 'NOT STARTED';
  if (execution?.state === 'EXECUTING') { executorState = 'EXECUTING'; executorTone = 'info'; }
  if (execution?.state === 'PENDING_VERIFICATION') { executorState = 'ACCEPTED'; executorTone = 'warning'; }
  if (execution?.state === 'COMPLETED') { executorState = 'EXECUTED'; executorTone = 'success'; }
  if (execution?.state === 'UNVERIFIED') { executorState = 'UNVERIFIED'; executorTone = 'warning'; }
  if (execution?.state === 'FAILED') { executorState = 'FAILED'; executorTone = 'danger'; }

  let verifyState = authorized && !execution ? 'NOT VERIFIED YET' : 'WAITING';
  let verifyTone: Tone = 'pending';
  if (execution?.state === 'PENDING_VERIFICATION') { verifyState = 'PENDING'; verifyTone = 'warning'; }
  if (execution?.state === 'COMPLETED') { verifyState = 'VERIFIED'; verifyTone = 'success'; }
  if (execution?.state === 'UNVERIFIED' || execution?.state === 'FAILED') { verifyState = 'UNVERIFIED'; verifyTone = 'danger'; }

  return [
    { label: 'AI proposal', state: action ? 'RECEIVED' : 'WAITING', detail: proposalDetail, tone: action ? 'info' : 'pending', icon: BrainCircuit },
    { label: 'Guard runtime policy', state: decision?.decision ?? 'WAITING', detail: decision ? decision.reasonCode : 'No Guard runtime decision observed yet.', tone: policyTone, icon: ShieldCheck },
    { label: 'Human', state: humanState, detail: humanState === 'REQUIRED' ? 'Human authorization required before protected execution.' : humanState === 'AUTHORIZED' ? 'Authorization is recorded for this action.' : 'No authorization is inferred.', tone: humanTone, icon: UserCheck },
    { label: 'Executor', state: executorState, detail: executorState === 'NOT EXECUTED' ? 'Protected egress did not run.' : executorState === 'NOT STARTED' ? 'Authorized, but protected execution has not started.' : 'State comes from the remediation execution record.', tone: executorTone, icon: ServerCog },
    { label: 'Verify', state: verifyState, detail: verifyState === 'VERIFIED' ? 'Independent read-back confirmed the expected external state.' : verifyState === 'NOT VERIFIED YET' ? 'Authorization exists, but no independently verified completion has been observed.' : 'No verified completion is claimed unless read-back succeeds.', tone: verifyTone, icon: BadgeCheck },
  ];
}

function readyLabel(ready?: boolean): { label: string; tone: Tone } {
  if (ready === undefined) return { label: 'NOT OBSERVED', tone: 'pending' };
  return ready ? { label: 'READY', tone: 'success' } : { label: 'NOT READY', tone: 'danger' };
}

function accessLabel(status: SystemStatus | null): { label: string; tone: Tone } {
  if (!status) return { label: 'NOT OBSERVED', tone: 'pending' };
  if (status.delegationEffectiveState === 'DENIED' || status.executorDelegationEffectiveState === 'DENIED') return { label: 'DENIED', tone: 'danger' };
  if (status.delegationEffectiveState === 'ACTIVE' && status.executorDelegationEffectiveState === 'ACTIVE') return { label: 'CONFIRMED', tone: 'success' };
  return { label: 'UNKNOWN', tone: 'warning' };
}

function identitiesLabel(proposalDid?: string | null, executorDid?: string | null): { label: string; tone: Tone } {
  if (!proposalDid || !executorDid) return { label: 'NOT OBSERVED', tone: 'pending' };
  if (proposalDid === executorDid) return { label: 'IDENTITY COLLISION', tone: 'danger' };
  return { label: 'SEPARATE', tone: 'success' };
}

export function ExecutiveDemoView({
  scenario,
  systemStatus,
  statusLoading,
  agentAnalysis,
  selectedAction,
  decision,
  remediationExecution,
  businessImpact = null,
  businessImpactLoading = false,
  businessImpactError = null,
}: Props) {
  const action = selectedAction ?? agentAnalysis?.action ?? null;
  const policyDecision = selectedAction ? decision : (agentAnalysis?.decision ?? decision);
  const currentReadiness = readiness(systemStatus, statusLoading);
  const outcome = observedOutcome(action, policyDecision, remediationExecution);
  const steps = trustPath(action, policyDecision, remediationExecution);
  const decisionTime = formatObservedDuration(elapsedMs(action?.createdAt, policyDecision?.evaluatedAt));
  const evaluation = readyLabel(systemStatus?.evaluationReady);
  const remediation = readyLabel(systemStatus?.protectedRemediationReady);
  const access = accessLabel(systemStatus);
  const identities = identitiesLabel(systemStatus?.agentDid, systemStatus?.executorDid);
  const enterpriseIntegrationState = systemStatus?.enterpriseIntegrationState ?? 'NOT OBSERVED';

  return (
    <Surface className="executive-demo" elevated aria-labelledby="executive-demo-title" data-testid="executive-demo-view">
      <header className="executive-demo-header">
        <div>
          <div className="executive-demo-product-lockup">
            <PrivacyGuardMark className="executive-demo-brand-mark" testId="executive-brand-mark" />
            <p className="eyebrow">Privacy Guard · Executive demo</p>
          </div>
          <h1 id="executive-demo-title">Use AI agents in sensitive workflows without giving the model security authority.</h1>
          <p className="executive-demo-subheadline">Keep private data, policy decisions and critical actions outside the model while preserving useful AI recommendations. Unsafe proposals can be blocked or minimized, protected remediation requires human authorization, and completion is claimed only after independent verification.</p>
        </div>
        <span className={`executive-demo-readiness executive-tone-${currentReadiness.tone}`} data-testid="executive-readiness">{currentReadiness.label}</span>
      </header>

      <div className="executive-demo-outcome-grid">
        <section className="executive-demo-block" aria-labelledby="executive-risk-title">
          <div className="executive-demo-block-title"><CircleAlert aria-hidden="true" /><h2 id="executive-risk-title">Business risk</h2></div>
          {scenario ? (
            <>
              <strong>{scenario.title}</strong>
              <p>{scenario.businessRisk}</p>
              <dl className="executive-demo-inline-facts"><div><dt>Protected asset</dt><dd>{scenario.protectedAsset}</dd></div></dl>
            </>
          ) : (
            <>
              <strong>Persisted incident</strong>
              <p>Resumed from the operational workspace. Demo scenario metadata is intentionally not inferred for this incident.</p>
              <dl className="executive-demo-inline-facts"><div><dt>Protected asset</dt><dd>{action?.resource ?? 'NOT OBSERVED'}</dd></div></dl>
            </>
          )}
        </section>
        <section className="executive-demo-block" aria-labelledby="executive-outcome-title">
          <div className="executive-demo-block-title"><BadgeCheck aria-hidden="true" /><h2 id="executive-outcome-title">Observed outcome</h2></div>
          <strong className="executive-demo-outcome" data-testid="executive-observed-outcome">{outcome}</strong>
          <dl className="executive-demo-inline-facts">
            <div><dt>Decision</dt><dd>{policyDecision?.decision ?? 'NOT OBSERVED'}</dd></div>
            <div><dt>Time to decision</dt><dd>{decisionTime}</dd></div>
          </dl>
        </section>
      </div>

      <ControlImpactSummary
        impact={businessImpact}
        loading={businessImpactLoading}
        error={businessImpactError}
        window="retained"
        compact
      />

      <section className="executive-demo-trust" aria-labelledby="executive-trust-title">
        <div className="executive-demo-section-heading">
          <p className="eyebrow">How the control works</p>
          <h2 id="executive-trust-title">Trust path</h2>
          <p className="executive-demo-mechanism">AI can propose. Policy decides. Humans authorize. Guard runtime executes.</p>
        </div>
        <ol className="executive-demo-trust-steps">
          {steps.map((step, index) => {
            const Icon = step.icon;
            return (
              <li key={step.label} className={`executive-demo-step executive-tone-${step.tone}`} data-testid={`executive-step-${step.label.toLowerCase().replaceAll(' ', '-')}`}>
                <div className="executive-demo-step-heading"><Icon aria-hidden="true" /><span>{step.label}</span></div>
                <strong>{step.state}</strong>
                <small title={step.detail}>{step.detail}</small>
                {index < steps.length - 1 && <ArrowRight className="executive-demo-arrow" aria-hidden="true" />}
              </li>
            );
          })}
        </ol>
      </section>

      <section className="executive-demo-proof" aria-labelledby="executive-proof-title" data-testid="executive-proof">
        <div className="executive-demo-proof-heading">
          <div className="executive-demo-block-title"><FileCheck2 aria-hidden="true" /><h2 id="executive-proof-title">Proof at a glance</h2></div>
          {(statusLoading || !systemStatus) && <span className="executive-demo-proof-state">{statusLoading ? 'Checking live status…' : 'Live status not loaded'}</span>}
        </div>

        <dl className="executive-demo-proof-grid">
          <div><dt>Policy evaluation</dt><dd className={`executive-tone-text-${evaluation.tone}`}>{evaluation.label}</dd></div>
          <div><dt>Protected remediation</dt><dd className={`executive-tone-text-${remediation.tone}`}>{remediation.label}</dd></div>
          <div><dt>Identity separation</dt><dd className={`executive-tone-text-${identities.tone}`}>{identities.label}</dd></div>
          <div><dt>Effective access</dt><dd className={`executive-tone-text-${access.tone}`}>{access.label}</dd></div>
          <div><dt>Enterprise integration</dt><dd>{enterpriseIntegrationState}</dd></div>
          <div><dt>Policy version</dt><dd>{policyDecision?.policyVersion ?? 'NOT OBSERVED'}</dd></div>
        </dl>
        <p className="executive-demo-proof-note">Facts come from the live system status and the observed policy decision; nothing is inferred while they are unavailable. Effective access means Guard runtime confirmed the separate Proposal and Executor callers against their own function grants. Enterprise integration READY does not prove external service success. Caller identities and integration details remain available in System readiness details.</p>
      </section>

      <footer className="executive-demo-actions">
        <ScreenManualDialog />
      </footer>
    </Surface>
  );
}
