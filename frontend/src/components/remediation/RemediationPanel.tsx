import { CheckCircle2, CircleAlert, Clock3, LockKeyhole, PlayCircle, RefreshCw, ShieldCheck } from 'lucide-react';
import type { ActionProposal, PolicyDecision, RemediationExecution } from '../../services/privacyGuardApi';

interface Props {
  action: ActionProposal | null;
  decision: PolicyDecision | null;
  execution: RemediationExecution | null;
  busy: boolean;
  onAuthorize: () => void;
  onExecute: () => void;
  onVerify: () => void;
}

const REQUIRED_REMEDIATION_FIELDS = ['incident_id', 'credential_id', 'reason'];

function stateCopy(execution: RemediationExecution | null): { execution: string; verification: string; final: string } {
  if (!execution) return { execution: 'NOT SENT', verification: 'NOT STARTED', final: 'NOT STARTED' };
  if (execution.state === 'EXECUTING') return { execution: 'CLAIMED / SENDING', verification: 'NOT STARTED', final: 'IN PROGRESS' };
  if (execution.state === 'PENDING_VERIFICATION') return { execution: 'ACCEPTED', verification: 'PENDING', final: 'IN PROGRESS' };
  if (execution.state === 'COMPLETED') return { execution: 'ACCEPTED', verification: 'VERIFIED', final: 'COMPLETED' };
  if (execution.state === 'UNVERIFIED') return { execution: execution.httpCode ? 'ACCEPTED OR AMBIGUOUS' : 'AMBIGUOUS', verification: 'UNVERIFIED', final: 'UNVERIFIED' };
  return { execution: 'BLOCKED / FAILED', verification: 'NOT VERIFIED', final: 'FAILED' };
}

function executableDecision(decision: PolicyDecision | null): boolean {
  return Boolean(decision
    && decision.decision !== 'DENY'
    && REQUIRED_REMEDIATION_FIELDS.every((field) => decision.allowedFields.includes(field)));
}

function authorizationTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'INVALID — BLOCKED' : date.toLocaleString();
}

export function RemediationPanel({ action, decision, execution, busy, onAuthorize, onExecute, onVerify }: Props) {
  const hasVerifiedExecutor = action?.action === 'revoke-credential';
  const hasApprovedDestination = Boolean(action?.host);
  const normalPayload = action?.normalPayload ?? {};
  const payloadEntries = Object.entries(normalPayload);
  const allowedPayloadEntries = payloadEntries.filter(([field]) => decision?.allowedFields.includes(field));
  const removedPayloadEntries = payloadEntries.filter(([field]) => decision?.redactedFields.includes(field));
  const decisionCanExecute = executableDecision(decision) && REQUIRED_REMEDIATION_FIELDS.every((field) => field in normalPayload);
  const statusAuthorized = action?.status === 'REMEDIATION_AUTHORIZED' || action?.status === 'REMEDIATED';
  const hasBoundAuthorization = Boolean(action?.remediationAuthorizedBy && action?.remediationAuthorizedAt);
  const legacyAuthorizationNeedsRebind = action?.status === 'REMEDIATION_AUTHORIZED' && !hasBoundAuthorization;
  const authorizationState = statusAuthorized ? (hasBoundAuthorization ? 'AUTHORIZED' : 'REAUTHORIZATION REQUIRED') : 'NOT AUTHORIZED';
  const canAuthorize = Boolean(hasVerifiedExecutor && hasApprovedDestination && action && decisionCanExecute
    && (action.status === 'EVALUATED' || legacyAuthorizationNeedsRebind));
  const canExecute = Boolean(hasVerifiedExecutor && hasApprovedDestination && action && decisionCanExecute
    && action.status === 'REMEDIATION_AUTHORIZED' && hasBoundAuthorization && !execution);
  const canVerify = Boolean(hasVerifiedExecutor && execution && (execution.state === 'PENDING_VERIFICATION' || execution.state === 'UNVERIFIED') && execution.operationId);
  const destinationChanged = execution?.failureCode === 'EXECUTION_DESTINATION_CHANGED';
  const state = stateCopy(execution);
  const proofState = execution ? 'ISSUED FOR EXECUTION' : hasBoundAuthorization && statusAuthorized ? 'ISSUED ON EXECUTE' : 'NOT ISSUED';
  const t3nProofState = execution?.httpCode ? 'VERIFIED' : execution ? 'NOT CONFIRMED' : 'NOT RUN';
  const executorBindingState = execution?.httpCode ? 'BOUND TO VERIFIED PROOF' : execution ? 'BOUND / NOT CONFIRMED' : 'CHECKED AT EXECUTION';

  return (
    <section className="card remediation-card" aria-labelledby="remediation-title">
      <div className="card-heading compact"><div className="section-icon section-icon-success"><LockKeyhole aria-hidden="true" /></div><div><p className="eyebrow">Secretless remediation</p><h2 id="remediation-title">Protected execution</h2></div></div>
      <p className="card-copy">The model selects field names only. Synthetic operational values are created and persisted by the trusted backend, then the T3N policy removes unnecessary fields before protected egress.</p>
      {action && !hasVerifiedExecutor && <p className="inline-notice">This action can be evaluated by the T3N policy, but this demo does not claim a protected executor or independent completion verifier for it. Full execution and read-back are currently implemented only for credential revocation.</p>}
      {hasVerifiedExecutor && decision?.decision === 'DENY' && <p className="inline-notice">A DENY decision cannot enter protected remediation.</p>}
      {hasVerifiedExecutor && decision && decision.decision !== 'DENY' && !decisionCanExecute && <p className="inline-notice">Execution is blocked because the policy-minimized result no longer contains all required remediation fields.</p>}

      {action && decision && (
        <div role="region" aria-label="T3N payload minimization">
          <div className="field-list"><span>Requested fields</span>{action.fields.map((field) => <code key={field}>{field}</code>)}</div>
          {decision.allowedFields.length > 0 && <div className="field-list"><span>Allowed for egress</span>{decision.allowedFields.map((field) => <code key={field}>{field}</code>)}</div>}
          {decision.redactedFields.length > 0 && <div className="field-list"><span>Removed before egress</span>{decision.redactedFields.map((field) => <code key={field}>{field}</code>)}</div>}
          {payloadEntries.length > 0 && <div className="field-list"><span>Trusted synthetic values</span>{payloadEntries.map(([field, value]) => <code key={field}>{field}={value}</code>)}</div>}
          {allowedPayloadEntries.length > 0 && <div className="field-list"><span>Protected egress payload</span>{allowedPayloadEntries.map(([field, value]) => <code key={field}>{field}={value}</code>)}</div>}
          {removedPayloadEntries.length > 0 && <p className="inline-notice">{removedPayloadEntries.length} trusted value{removedPayloadEntries.length === 1 ? ' was' : 's were'} removed by policy and will not be serialized into the external request.</p>}
        </div>
      )}

      {hasVerifiedExecutor && action && decisionCanExecute && (
        <div className="remediation-state-panel" role="region" aria-label="Approved remediation destination and authorization proof status">
          <div><span>Policy decision</span><strong>{decision?.decision}</strong></div>
          <div><span>Approved destination</span><strong>{action.host || 'MISSING — BLOCKED'}</strong></div>
          <div><span>Human authorization</span><strong>{authorizationState}</strong></div>
          {hasBoundAuthorization && <div><span>Authorized by</span><strong>{action.remediationAuthorizedBy}</strong></div>}
          {hasBoundAuthorization && action.remediationAuthorizedAt && <div><span>Authorized at</span><strong>{authorizationTimestamp(action.remediationAuthorizedAt)}</strong></div>}
          <div><span>One-time authorization proof</span><strong>{proofState}</strong></div>
          <div><span>T3N execution proof check</span><strong>{t3nProofState}</strong></div>
          <div><span>Protected Executor identity</span><strong>{executorBindingState}</strong></div>
        </div>
      )}
      {legacyAuthorizationNeedsRebind && <div className="feedback feedback-error remediation-status-message" role="alert"><CircleAlert aria-hidden="true" /><span>This authorization predates operator provenance binding. Re-authorize it with the current authenticated operator before protected execution.</span></div>}
      {hasVerifiedExecutor && action && decisionCanExecute && !action.host && <div className="feedback feedback-error remediation-status-message" role="alert"><CircleAlert aria-hidden="true" /><span>Execution is blocked because this action has no approved destination. Create and evaluate a new action before authorizing remediation.</span></div>}
      {canAuthorize && <button className="button button-primary" type="button" onClick={onAuthorize} disabled={busy}><ShieldCheck aria-hidden="true" />{legacyAuthorizationNeedsRebind ? 'Re-authorize credential revocation' : 'Authorize credential revocation'}</button>}
      {canExecute && <>
        <div className="success-state"><ShieldCheck aria-hidden="true" /><span>Human authorization is bound to the authenticated operator, exact destination, trusted payload, policy and Protected Executor. Execution issues an Ed25519-signed one-time proof that is checked by the gateway and again inside T3N before protected egress.</span></div>
        <button className="button button-primary" type="button" onClick={onExecute} disabled={busy}><PlayCircle aria-hidden="true" />Execute protected credential revocation</button>
      </>}

      {hasVerifiedExecutor && (execution || statusAuthorized) && (
        <div className="remediation-state-panel" role="region" aria-label="Remediation execution and verification status">
          <div><span>Authorization</span><strong>{authorizationState}</strong></div>
          <div><span>Execution</span><strong>{state.execution}</strong></div>
          <div><span>Verification</span><strong>{state.verification}</strong></div>
          <div><span>Final state</span><strong>{state.final}</strong></div>
        </div>
      )}

      {hasVerifiedExecutor && execution?.state === 'PENDING_VERIFICATION' && <div className="inline-notice remediation-status-message"><Clock3 aria-hidden="true" /><span>The one-time proof passed the protected T3N execution boundary and the side effect was accepted, but completion still depends on independent verification.</span></div>}
      {hasVerifiedExecutor && execution?.state === 'UNVERIFIED' && <div className="inline-notice remediation-status-message"><CircleAlert aria-hidden="true" /><span>The outcome is ambiguous or the external state was not confirmed. The system will not send the side effect again automatically.</span></div>}
      {hasVerifiedExecutor && destinationChanged && <div className="feedback feedback-error remediation-status-message" role="alert"><CircleAlert aria-hidden="true" /><span>Destination changed. The protected configuration no longer matches the destination that was approved. Create a new action, evaluate the intended destination, and authorize it before executing again.</span></div>}
      {hasVerifiedExecutor && execution?.state === 'FAILED' && !destinationChanged && <div className="feedback feedback-error remediation-status-message"><CircleAlert aria-hidden="true" /><span>Execution failed before a verified completion state. Review the audit trail before any new action.</span></div>}
      {hasVerifiedExecutor && execution?.state === 'COMPLETED' && <div className="success-state"><CheckCircle2 aria-hidden="true" /><span>Independent read-back verified the expected external state. This remediation is now COMPLETED.</span></div>}

      {canVerify && <button className="button button-secondary" type="button" onClick={onVerify} disabled={busy}><RefreshCw aria-hidden="true" />Verify external state</button>}
      {hasVerifiedExecutor && execution && <p className="remediation-meta">Verification attempts: {execution.verificationAttempts}{execution.failureCode ? ` · Last state: ${execution.failureCode}` : ''}</p>}
    </section>
  );
}
