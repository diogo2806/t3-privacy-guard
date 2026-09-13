import { CheckCircle2, CircleAlert, Clock3, LockKeyhole, PlayCircle, RefreshCw, ShieldCheck } from 'lucide-react';
import type { ActionProposal, PolicyDecision, RemediationExecution } from '../../services/privacyGuardApi';

interface Props {
  action: ActionProposal | null;
  decision: PolicyDecision | null;
  execution: RemediationExecution | null;
  executorDid?: string | null;
  busy: boolean;
  onAuthorize: () => void;
  onExecute: () => void;
  onVerify: () => void;
}

function stateCopy(execution: RemediationExecution | null): { execution: string; verification: string; final: string } {
  if (!execution) return { execution: 'NOT SENT', verification: 'NOT STARTED', final: 'NOT STARTED' };
  if (execution.state === 'EXECUTING') return { execution: 'CLAIMED / SENDING', verification: 'NOT STARTED', final: 'IN PROGRESS' };
  if (execution.state === 'PENDING_VERIFICATION') return { execution: 'ACCEPTED', verification: 'PENDING', final: 'IN PROGRESS' };
  if (execution.state === 'COMPLETED') return { execution: 'ACCEPTED', verification: 'VERIFIED', final: 'COMPLETED' };
  if (execution.state === 'UNVERIFIED') return { execution: execution.httpCode ? 'ACCEPTED OR AMBIGUOUS' : 'AMBIGUOUS', verification: 'UNVERIFIED', final: 'UNVERIFIED' };
  return { execution: 'BLOCKED / FAILED', verification: 'NOT VERIFIED', final: 'FAILED' };
}

export function RemediationPanel({ action, decision, execution, executorDid, busy, onAuthorize, onExecute, onVerify }: Props) {
  const hasVerifiedExecutor = action?.action === 'revoke-credential';
  const hasApprovedDestination = Boolean(action?.host);
  const authorized = action?.status === 'REMEDIATION_AUTHORIZED' || action?.status === 'REMEDIATED';
  const canAuthorize = Boolean(hasVerifiedExecutor && hasApprovedDestination && action && decision?.decision === 'ALLOW' && action.status === 'EVALUATED');
  const canExecute = Boolean(hasVerifiedExecutor && hasApprovedDestination && action && decision?.decision === 'ALLOW' && action.status === 'REMEDIATION_AUTHORIZED' && !execution);
  const canVerify = Boolean(hasVerifiedExecutor && execution && (execution.state === 'PENDING_VERIFICATION' || execution.state === 'UNVERIFIED') && execution.operationId);
  const destinationChanged = execution?.failureCode === 'EXECUTION_DESTINATION_CHANGED';
  const proofConfirmed = Boolean(execution && (execution.httpCode || destinationChanged));
  const proofState = proofConfirmed ? 'CONSUMED' : execution ? 'NOT CONFIRMED' : authorized ? 'ISSUED ON EXECUTE' : 'NOT ISSUED';
  const gatewayProofState = proofConfirmed ? 'VERIFIED' : execution ? 'NOT CONFIRMED' : 'NOT RUN';
  const t3nProofState = proofConfirmed ? 'T3N PROOF VERIFIED' : execution ? 'NOT CONFIRMED' : 'NOT RUN';
  const state = stateCopy(execution);

  return (
    <section className="card remediation-card" aria-labelledby="remediation-title">
      <div className="card-heading compact"><div className="section-icon section-icon-success"><LockKeyhole aria-hidden="true" /></div><div><p className="eyebrow">Secretless remediation</p><h2 id="remediation-title">Protected execution</h2></div></div>
      <p className="card-copy">The protected Executor DID is necessary but not sufficient. Execution also requires the same one-time Ed25519 human authorization proof to pass at the gateway and again inside the T3N contract before protected secrets or egress are available.</p>
      {action && !hasVerifiedExecutor && <p className="inline-notice">This action can be evaluated by the T3N policy, but this demo does not claim a protected executor or independent completion verifier for it. Full execution and read-back are currently implemented only for credential revocation.</p>}
      {(!action || hasVerifiedExecutor) && decision?.decision !== 'ALLOW' && <p className="inline-notice">A persisted ALLOW decision is required before credential revocation can be authorized.</p>}
      {hasVerifiedExecutor && action && decision?.decision === 'ALLOW' && (
        <div className="remediation-state-panel" role="region" aria-label="Approved remediation destination and authorization status">
          <div><span>Policy decision</span><strong>ALLOW</strong></div>
          <div><span>Approved destination</span><strong>{action.host || 'MISSING — BLOCKED'}</strong></div>
          <div><span>Human authorization</span><strong>{authorized ? 'AUTHORIZED' : 'NOT AUTHORIZED'}</strong></div>
          <div><span>Protected Executor DID</span><strong>{executorDid || 'UNAVAILABLE — BLOCKED'}</strong></div>
        </div>
      )}
      {hasVerifiedExecutor && action && decision?.decision === 'ALLOW' && !action.host && <div className="feedback feedback-error remediation-status-message" role="alert"><CircleAlert aria-hidden="true" /><span>Execution is blocked because this action has no approved destination. Create and evaluate a new action before authorizing remediation.</span></div>}
      {canAuthorize && <button className="button button-primary" type="button" onClick={onAuthorize} disabled={busy}><ShieldCheck aria-hidden="true" />Authorize credential revocation</button>}
      {canExecute && <>
        <div className="success-state"><ShieldCheck aria-hidden="true" /><span>Human authorization is recorded for this action and destination. The backend will issue a short-lived one-time proof only when protected execution starts; changing the action, policy, destination or Executor invalidates the binding.</span></div>
        <button className="button button-primary" type="button" onClick={onExecute} disabled={busy}><PlayCircle aria-hidden="true" />Execute protected credential revocation</button>
      </>}

      {hasVerifiedExecutor && (execution || authorized) && (
        <div className="remediation-state-panel" role="region" aria-label="Remediation execution and verification status">
          <div><span>Human authorization</span><strong>{authorized ? 'AUTHORIZED' : 'NOT AUTHORIZED'}</strong></div>
          <div><span>One-time authorization proof</span><strong>{proofState}</strong></div>
          <div><span>Gateway proof check</span><strong>{gatewayProofState}</strong></div>
          <div><span>T3N contract proof check</span><strong>{t3nProofState}</strong></div>
          <div><span>Execution</span><strong>{state.execution}</strong></div>
          <div><span>External-state verification</span><strong>{state.verification}</strong></div>
          <div><span>Final state</span><strong>{state.final}</strong></div>
        </div>
      )}

      {hasVerifiedExecutor && execution?.state === 'PENDING_VERIFICATION' && <div className="inline-notice remediation-status-message"><Clock3 aria-hidden="true" /><span>The side effect was accepted after both proof checks. Completion still depends on independent verification of the external state.</span></div>}
      {hasVerifiedExecutor && execution?.state === 'UNVERIFIED' && <div className="inline-notice remediation-status-message"><CircleAlert aria-hidden="true" /><span>The outcome is ambiguous or the external state was not confirmed. The system will not send the side effect again automatically.</span></div>}
      {hasVerifiedExecutor && destinationChanged && <div className="feedback feedback-error remediation-status-message" role="alert"><CircleAlert aria-hidden="true" /><span>The authorization proof was valid, but the protected destination changed after approval. Create a new action, evaluate the intended destination, and authorize it before executing again.</span></div>}
      {hasVerifiedExecutor && execution?.state === 'FAILED' && !destinationChanged && <div className="feedback feedback-error remediation-status-message"><CircleAlert aria-hidden="true" /><span>Execution failed before a verified completion state. A failed request does not prove that both authorization boundaries accepted the proof; review the audit trail before any new action.</span></div>}
      {hasVerifiedExecutor && execution?.state === 'COMPLETED' && <div className="success-state"><CheckCircle2 aria-hidden="true" /><span>Both authorization boundaries accepted the one-time proof, and independent read-back verified the expected external state. This remediation is now COMPLETED.</span></div>}

      {canVerify && <button className="button button-secondary" type="button" onClick={onVerify} disabled={busy}><RefreshCw aria-hidden="true" />Verify external state</button>}
      {hasVerifiedExecutor && execution && <p className="remediation-meta">Verification attempts: {execution.verificationAttempts}{execution.failureCode ? ` · Last state: ${execution.failureCode}` : ''}</p>}
    </section>
  );
}
