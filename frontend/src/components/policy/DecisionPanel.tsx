import { CheckCircle2, CircleSlash2, Scissors } from 'lucide-react';
import type { PolicyDecision } from '../../services/privacyGuardApi';

export function DecisionPanel({ decision }: { decision: PolicyDecision | null }) {
  if (!decision) return <section className="card"><p className="eyebrow">T3N policy decision</p><h2>Awaiting evaluation</h2><p className="empty-copy">Select a proposal or run a scenario to obtain a decision from the registered contract.</p></section>;
  const Icon = decision.decision === 'ALLOW' ? CheckCircle2 : decision.decision === 'REDACT' ? Scissors : CircleSlash2;
  return (
    <section className={`card decision-card decision-${decision.decision.toLowerCase()}`}>
      <div className="decision-hero"><Icon aria-hidden="true" /><div><p className="eyebrow">T3N policy decision</p><h2>{decision.decision}</h2><p>{decision.reason}</p></div></div>
      <div className="decision-code"><span>Reason code</span><code>{decision.reasonCode}</code></div>
      {decision.redactedFields.length > 0 && <div className="field-list"><span>Fields removed by minimization</span>{decision.redactedFields.map((field) => <code key={field}>{field}</code>)}</div>}
      {decision.allowedFields.length > 0 && <div className="field-list"><span>Allowed field names</span>{decision.allowedFields.map((field) => <code key={field}>{field}</code>)}</div>}
    </section>
  );
}
