import { BriefcaseBusiness, CheckCircle2, CircleAlert, Clock3, ShieldCheck } from 'lucide-react';
import type { ActionProposal, AgentAnalysis, Incident, PolicyDecision, RemediationExecution } from '../../services/privacyGuardApi';
import type { EnterpriseScenarioDefinition } from '../scenarios/scenarioDefinitions';
import { SectionHeader } from '../ui/SectionHeader';
import { Surface } from '../ui/Surface';

interface Props {
  scenario: EnterpriseScenarioDefinition;
  incident: Incident | null;
  selectedAction: ActionProposal | null;
  decision: PolicyDecision | null;
  remediationExecution: RemediationExecution | null;
  agentAnalysis: AgentAnalysis | null;
}

const NOT_OBSERVED = 'Not yet observed';
const NOT_VERIFIED = 'Not verified yet';

function elapsedMs(start?: string | null, end?: string | null): number | null {
  if (!start || !end) return null;
  const startMs = Date.parse(start);
  const endMs = Date.parse(end);
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs < startMs) return null;
  return endMs - startMs;
}

export function formatObservedDuration(milliseconds: number | null): string {
  if (milliseconds === null) return NOT_OBSERVED;
  if (milliseconds < 1_000) return `${Math.round(milliseconds)} ms`;
  if (milliseconds <= 60_000) return `${(milliseconds / 1_000).toFixed(1)} s`;
  const minutes = Math.floor(milliseconds / 60_000);
  const seconds = (milliseconds % 60_000) / 1_000;
  return `${minutes}m ${seconds.toFixed(1)}s`;
}

function list(values: string[]): string {
  return values.length > 0 ? values.join(', ') : 'None observed';
}

function isAuthorized(action: ActionProposal | null): boolean {
  return action?.status === 'REMEDIATION_AUTHORIZED' || action?.status === 'REMEDIATED';
}

function hasAuthorizationProvenance(action: ActionProposal | null): boolean {
  return Boolean(action?.remediationAuthorizedBy && action?.remediationAuthorizedAt);
}

function humanAuthorization(action: ActionProposal | null, decision: PolicyDecision | null): string {
  if (!action) return NOT_OBSERVED;
  if (isAuthorized(action)) return hasAuthorizationProvenance(action) ? 'AUTHORIZED' : 'LEGACY UNBOUND';
  if (action.action === 'revoke-credential' && decision?.decision === 'ALLOW') return 'REQUIRED';
  return 'NOT APPLICABLE';
}

function authorizationTime(value?: string | null): string {
  if (!value) return 'Not recorded — legacy authorization';
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? 'Not recorded — invalid timestamp' : timestamp.toLocaleString();
}

function approvedDestination(action: ActionProposal | null, decision: PolicyDecision | null): string {
  if (!action) return NOT_OBSERVED;
  if (isAuthorized(action)) return action.host ?? 'MISSING — BLOCKED';
  if (action.action === 'revoke-credential' && decision?.decision === 'ALLOW') return action.host ? 'Not authorized yet' : 'MISSING — BLOCKED';
  return 'NOT APPLICABLE';
}

function policyAllowedDestination(action: ActionProposal | null, decision: PolicyDecision | null): string {
  if (!action || !decision) return NOT_OBSERVED;
  if (decision.decision !== 'ALLOW') return 'NOT ESTABLISHED';
  return action.host ?? 'No destination requested';
}

function policyAllowedAction(action: ActionProposal | null, decision: PolicyDecision | null): string {
  if (!action || decision?.decision !== 'ALLOW') return NOT_OBSERVED;
  return action.action;
}

function externalAction(action: ActionProposal | null, execution: RemediationExecution | null): string {
  if (!action) return NOT_OBSERVED;
  if (!execution) return 'NOT STARTED';
  if (execution.state === 'EXECUTING') return 'IN PROGRESS';
  if (execution.state === 'PENDING_VERIFICATION') return 'ACCEPTED — VERIFICATION PENDING';
  if (execution.state === 'COMPLETED') return 'VERIFIED';
  if (execution.state === 'UNVERIFIED') return 'UNVERIFIED';
  return 'FAILED';
}

function verifiedFinalState(action: ActionProposal | null, execution: RemediationExecution | null): string {
  if (execution?.state !== 'COMPLETED') return 'NOT VERIFIED';
  return action?.action === 'revoke-credential' ? 'REVOKED — VERIFIED' : 'VERIFIED';
}

function currentResult(
  threatDecision: PolicyDecision | null,
  responseAction: ActionProposal | null,
  responseDecision: PolicyDecision | null,
  execution: RemediationExecution | null,
): string {
  if (execution?.state === 'COMPLETED') return 'Independent read-back verified the expected external state.';
  if (execution?.state === 'PENDING_VERIFICATION') return 'External action accepted. Completion is not yet verified.';
  if (execution?.state === 'UNVERIFIED') return 'The external outcome remains unverified. No successful remediation is claimed.';
  if (execution?.state === 'FAILED') return 'Execution failed without a verified external outcome.';
  if (execution?.state === 'EXECUTING') return 'Protected execution is in progress. No final outcome is claimed yet.';
  if (isAuthorized(responseAction) && !hasAuthorizationProvenance(responseAction)) return 'Authorization exists without bound operator provenance. Re-authorization is required before protected execution.';
  if (isAuthorized(responseAction)) return 'Authorized by an authenticated application operator. Protected execution has not started.';
  if (responseAction?.action === 'revoke-credential' && responseDecision?.decision === 'ALLOW') return 'Policy allows the action. Human authorization is still required.';
  if (responseDecision?.decision === 'REDACT') return 'T3N requires a smaller data scope before execution.';
  if (responseDecision?.decision === 'DENY') return 'T3N blocked the proposed action before protected egress.';
  if (threatDecision?.decision === 'DENY') return 'T3N blocked the proposed action before protected egress.';
  if (threatDecision?.decision === 'REDACT') return 'T3N requires a smaller data scope before execution.';
  if (threatDecision?.decision === 'ALLOW') return 'Policy allows the proposal to continue, but that is not authorization or execution.';
  return 'No threat has been analyzed yet.';
}

function requestedDestination(action: ActionProposal | null): string {
  if (!action) return NOT_OBSERVED;
  return action.host ?? 'No destination requested';
}

function policyDestination(action: ActionProposal | null, decision: PolicyDecision | null): string {
  if (!action) return NOT_OBSERVED;
  if (!action.host) return 'No destination requested';
  if (!decision) return `${action.host} — not evaluated`;
  if (decision.decision === 'DENY') return `${action.host} — blocked with proposal`;
  return `${action.host} — policy evaluated`;
}

export function BusinessOutcomeSummary({ scenario, incident, selectedAction, decision, remediationExecution, agentAnalysis }: Props) {
  const threatAction = agentAnalysis?.action ?? selectedAction;
  const threatDecision = agentAnalysis?.decision ?? decision;
  const policyDecisionTime = formatObservedDuration(elapsedMs(threatAction?.createdAt, threatDecision?.evaluatedAt));
  const verifiedOutcomeMs = remediationExecution?.state === 'COMPLETED' && remediationExecution.completedAt
    ? elapsedMs(selectedAction?.createdAt, remediationExecution.completedAt)
    : null;
  const verifiedOutcomeTime = remediationExecution?.state === 'COMPLETED' && remediationExecution.completedAt && verifiedOutcomeMs !== null
    ? formatObservedDuration(verifiedOutcomeMs)
    : NOT_VERIFIED;
  const outcomeText = currentResult(threatDecision, selectedAction, decision, remediationExecution);
  const successful = remediationExecution?.state === 'COMPLETED';
  const unresolved = remediationExecution?.state === 'FAILED' || remediationExecution?.state === 'UNVERIFIED';
  const authorized = isAuthorized(selectedAction);
  const authorizationBound = hasAuthorizationProvenance(selectedAction);

  return (
    <Surface className="business-outcome-card" aria-labelledby="business-outcome-title">
      <SectionHeader
        eyebrow="Business outcome"
        title={successful ? 'Credential compromise contained' : 'Risk → control → observed result'}
        titleId="business-outcome-title"
        icon={successful ? <CheckCircle2 aria-hidden="true" /> : unresolved ? <CircleAlert aria-hidden="true" /> : <BriefcaseBusiness aria-hidden="true" />}
        tone={successful ? 'success' : unresolved ? 'danger' : 'default'}
      />
      <p className="business-outcome-current" role="status">{outcomeText}</p>

      <dl className="business-context-grid">
        <div><dt>Business risk</dt><dd>{scenario.businessRisk}</dd></div>
        <div><dt>Protected asset</dt><dd>{scenario.protectedAsset}</dd></div>
        <div><dt>Target business outcome</dt><dd>{scenario.businessOutcome}</dd></div>
        <div><dt>Success definition</dt><dd>{scenario.successDefinition}</dd></div>
      </dl>

      <div className="business-outcome-sections">
        <section className="business-outcome-section" aria-labelledby="threat-observed-title">
          <div className="business-outcome-section-heading"><CircleAlert aria-hidden="true" /><h3 id="threat-observed-title">Threat observed</h3></div>
          <dl className="business-outcome-grid">
            <div><dt>Incident severity</dt><dd>{incident?.severity ?? NOT_OBSERVED}</dd></div>
            <div><dt>Agent action</dt><dd>{threatAction?.action ?? NOT_OBSERVED}</dd></div>
            <div><dt>Protected resource</dt><dd>{threatAction?.resource ?? NOT_OBSERVED}</dd></div>
            <div><dt>Requested destination</dt><dd>{requestedDestination(threatAction)}</dd></div>
            <div><dt>Requested field names</dt><dd>{threatAction ? `${threatAction.fields.length} · ${list(threatAction.fields)}` : NOT_OBSERVED}</dd></div>
            <div><dt>Requested private refs</dt><dd>{threatAction ? `${threatAction.privateRefs.length} · ${list(threatAction.privateRefs)}` : NOT_OBSERVED}</dd></div>
          </dl>
        </section>

        <section className="business-outcome-section" aria-labelledby="t3n-control-title">
          <div className="business-outcome-section-heading"><ShieldCheck aria-hidden="true" /><h3 id="t3n-control-title">T3N control outcome</h3></div>
          <dl className="business-outcome-grid">
            <div><dt>Policy decision</dt><dd>{threatDecision?.decision ?? NOT_OBSERVED}</dd></div>
            <div><dt>Reason code</dt><dd>{threatDecision?.reasonCode ?? NOT_OBSERVED}</dd></div>
            <div><dt>Destination</dt><dd>{policyDestination(threatAction, threatDecision)}</dd></div>
            <div><dt>Policy-allowed field names</dt><dd>{threatDecision ? `${threatDecision.allowedFields.length} · ${list(threatDecision.allowedFields)}` : NOT_OBSERVED}</dd></div>
            <div><dt>Policy-redacted field names</dt><dd>{threatDecision ? `${threatDecision.redactedFields.length} · ${list(threatDecision.redactedFields)}` : NOT_OBSERVED}</dd></div>
            <div><dt>Policy-allowed private refs</dt><dd>{threatDecision ? `${threatDecision.allowedPrivateRefs.length} · ${list(threatDecision.allowedPrivateRefs)}` : NOT_OBSERVED}</dd></div>
            <div><dt>Policy-redacted private refs</dt><dd>{threatDecision ? `${threatDecision.redactedPrivateRefs.length} · ${list(threatDecision.redactedPrivateRefs)}` : NOT_OBSERVED}</dd></div>
            <div><dt>Policy decision time</dt><dd>{policyDecisionTime}</dd></div>
          </dl>
          <p className="business-outcome-note">Field entries describe policy decisions over field names. Private refs are logical categories, not resolved private values. Neither is presented as proof that normal field values crossed or were removed from protected egress.</p>
        </section>

        <section className="business-outcome-section" aria-labelledby="authorized-response-title">
          <div className="business-outcome-section-heading"><Clock3 aria-hidden="true" /><h3 id="authorized-response-title">Authorized response</h3></div>
          <dl className="business-outcome-grid">
            <div><dt>Policy-allowed action</dt><dd>{policyAllowedAction(selectedAction, decision)}</dd></div>
            <div><dt>Human authorization</dt><dd>{humanAuthorization(selectedAction, decision)}</dd></div>
            {authorized && <div><dt>Authorized by</dt><dd>{authorizationBound ? selectedAction?.remediationAuthorizedBy : 'Not recorded — legacy authorization'}</dd></div>}
            {authorized && <div><dt>Authorized at</dt><dd>{authorizationTime(selectedAction?.remediationAuthorizedAt)}</dd></div>}
            <div><dt>Policy-allowed destination</dt><dd>{policyAllowedDestination(selectedAction, decision)}</dd></div>
            <div><dt>Approved destination</dt><dd>{approvedDestination(selectedAction, decision)}</dd></div>
            <div><dt>External action</dt><dd>{externalAction(selectedAction, remediationExecution)}</dd></div>
            <div><dt>Verified final state</dt><dd>{verifiedFinalState(selectedAction, remediationExecution)}</dd></div>
            <div><dt>Time to verified outcome</dt><dd>{verifiedOutcomeTime}</dd></div>
            <div><dt>Verification attempts</dt><dd>{remediationExecution ? remediationExecution.verificationAttempts : NOT_OBSERVED}</dd></div>
          </dl>
        </section>
      </div>
    </Surface>
  );
}
