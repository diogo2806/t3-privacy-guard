import { LockKeyhole, PlayCircle, ShieldCheck } from 'lucide-react';
import type { ActionProposal, PolicyDecision } from '../../services/privacyGuardApi';

interface Props { action: ActionProposal | null; decision: PolicyDecision | null; busy: boolean; onAuthorize: () => void; onExecute: () => void; }

export function RemediationPanel({ action, decision, busy, onAuthorize, onExecute }: Props) {
  const canAuthorize = Boolean(action && decision?.decision === 'ALLOW' && action.status === 'EVALUATED');
  const canExecute = Boolean(action && decision?.decision === 'ALLOW' && action.status === 'REMEDIATION_AUTHORIZED');
  const completed = action?.status === 'REMEDIATED';
  return (
    <section className="card remediation-card">
      <div className="card-heading compact"><div className="section-icon section-icon-success"><LockKeyhole aria-hidden="true" /></div><div><p className="eyebrow">Secretless remediation</p><h2>Protected execution</h2></div></div>
      <p className="card-copy">The upstream credential stays in the tenant private map. The browser, Java backend and AI agent receive no secret value.</p>
      {decision?.decision !== 'ALLOW' && <p className="inline-notice">A persisted ALLOW decision is required before remediation can be authorized.</p>}
      {canAuthorize && <button className="button button-primary" type="button" onClick={onAuthorize} disabled={busy}><ShieldCheck aria-hidden="true" />Authorize remediation</button>}
      {canExecute && <>
        <div className="success-state"><ShieldCheck aria-hidden="true" /><span>Human authorization is recorded. Execution will use a short-lived, one-time authorization proof bound to this exact action.</span></div>
        <button className="button button-primary" type="button" onClick={onExecute} disabled={busy}><PlayCircle aria-hidden="true" />Execute protected remediation</button>
      </>}
      {completed && <div className="success-state"><ShieldCheck aria-hidden="true" /><span>Protected remediation completed with a consumed one-time authorization proof. Review the audit trail for the sanitized result.</span></div>}
    </section>
  );
}
