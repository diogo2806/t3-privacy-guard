import { ShieldAlert } from 'lucide-react';

export function EmptyState({ onRun, busy }: { onRun: () => void; busy: boolean }) {
  return (
    <section className="empty-state">
      <ShieldAlert aria-hidden="true" />
      <h2>Prove the security boundary</h2>
      <p>Start with an AI-driven exfiltration attempt. The request is evaluated by the T3N contract, not trusted because the model proposed it.</p>
      <button type="button" className="button button-danger" onClick={onRun} disabled={busy}>{busy ? 'Running scenario…' : 'Run attack scenario'}</button>
    </section>
  );
}
