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

function stateCopy(execution: RemediationExecution | null): { execution: string; verification: string; final: string } {
  if (!execution) return { execution: 'NOT SENT', verification: 'NOT STARTED', final: 'NOT STARTED' };
  if (execution.state === 'EXECUTING') return { execution: 'CLAIMED / SENDING', verification: 'NOT STARTED', final: 'IN PROGRESS' };
  if (execution.state === 'PENDING_VERIFICATION') return { execution: 'ACCEPTED', verification: 'PENDING', final: 'IN PROGRESS' };
  if (execution.state === 'COMPLETED') return { execution: 'ACCEPTED', verification: 'VERIFIED', final: 'COMPLETED' };
  if (execution.state === 'UNVERIFIED') return { execution: execution.httpCode ? 'ACCEPTED OR AMBIGUOUS' : 'AMBIGUOUS', verification: 'UNVERIFIED', final: 'UNVERIFIED' };
  return { execution: 'FAILED', verification: 'NOT VERIFIED', final: 'FAILED' };
}

export function RemediationPanel({ action, decision, execution, busy, onAuthorize, onExecute, onVerify }: Props) {
  const hasVerifiedExecutor = action?.action === 'revoke-credential';
  const canAuthorize = Boolean(hasVerifiedExecutor && action && decision?.decision === 'ALLOW' && action.status === 'EVALUATED');
  const canExecute = Boolean(hasVerifiedExecutor && action && decision?.decision === 'ALLOW' && action.status === 'REMEDIATION_AUTHORIZED' && !execution);
  const canVerify = Boolean(hasVerifiedExecutor && execution && (execution.state === 'PENDING_VERIFICATION' || execution.state === 'UNVERIFIED') && execution.operationId);
  const state = stateCopy(execution);

  return (
    <section className="card remediation-card" aria-labelledby="remediation-title">
      <div className="card-heading compact"><div className="section-icon section-icon-success"><LockKeyhole aria-hidden="true" /></div><div><p className="eyebrow">Secretless remediation</p><h2 id="remediation-title">Protected execution</h2></div></div>
      <p className="card-copy">The upstream credential stays in the tenant private map. A provider acknowledgement is not called completed until an independent read-back confirms the expected external state.</p>
      {action && !hasVerifiedExecutor && <p className="inline-notice">This action can be evaluated by the T3N policy, but this demo does not claim a protected executor or independent completion verifier for it. Full execution and read-back are currently implemented only for credential revocation.</p>}
      {(!action || hasVerifiedExecutor) && decision?.decision !== 'ALLOW' && <p className="inline-notice">A persisted ALLOW decision is required before credential revocation can be authorized.</p>}
      {canAuthorize && <button className="button button-primary" type="button" onClick={onAuthorize} disabled={busy}><ShieldCheck aria-hidden="true" />Authorize credential revocation</button>}
      {canExecute && <>
        <div className="success-state"><ShieldCheck aria-hidden="true" /><span>Human authorization is recorded. Execution will use a one-time proof and a stable idempotency key.</span></div>
        <button className="button button-primary" type="button" onClick={onExecute} disabled={busy}><PlayCircle aria-hidden="true" />Execute protected credential revocation</button>
      </>}

      {hasVerifiedExecutor && (execution || action?.status === 'REMEDIATION_AUTHORIZED' || action?.status === 'REMEDIATED') && (
        <div className="remediation-state-panel" aria-label="Remediation execution and verification status">
          <div><span>Authorization</span><strong>{action?.status === 'REMEDIATION_AUTHORIZED' || action?.status === 'REMEDIATED' ? 'AUTHORIZED' : 'NOT AUTHORIZED'}</strong></div>
          <div><span>Execution</span><strong>{state.execution}</strong></div>
          <div><span>Verification</span><strong>{state.verification}</strong></div>
          <div><span>Final state</span><strong>{state.final}</strong></div>
        </div>
      )}

      {hasVerifiedExecutor && execution?.state === 'PENDING_VERIFICATION' && <div className="inline-notice remediation-status-message"><Clock3 aria-hidden="true" /><span>The side effect was accepted, but completion still depends on independent verification.</span></div>}
      {hasVerifiedExecutor && execution?.state === 'UNVERIFIED' && <div className="inline-notice remediation-status-message"><CircleAlert aria-hidden="true" /><span>The outcome is ambiguous or the external state was not confirmed. The system will not send the side effect again automatically.</span></div>}
      {hasVerifiedExecutor && execution?.state === 'FAILED' && <div className="feedback feedback-error remediation-status-message"><CircleAlert aria-hidden="true" /><span>Execution failed before a verified completion state. Review the audit trail before any new action.</span></div>}
      {hasVerifiedExecutor && execution?.state === 'COMPLETED' && <div className="success-state"><CheckCircle2 aria-hidden="true" /><span>Independent read-back verified the expected external state. This remediation is now COMPLETED.</span></div>}

      {canVerify && <button className="button button-secondary" type="button" onClick={onVerify} disabled={busy}><RefreshCw aria-hidden="true" />Verify external state</button>}
      {hasVerifiedExecutor && execution && <p className="remediation-meta">Verification attempts: {execution.verificationAttempts}{execution.failureCode ? ` · Last state: ${execution.failureCode}` : ''}</p>}
    </section>
  );
}
