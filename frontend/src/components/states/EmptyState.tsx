import { ShieldAlert } from 'lucide-react';

export function EmptyState(_: { onRun: () => void; busy: boolean }) {
  return (
    <section className="empty-state">
      <ShieldAlert aria-hidden="true" />
      <h2>No incident selected yet</h2>
      <p>Use the AI agent prompt panel above to run the attack prompt or submit a legitimate instruction. The model proposes an action and T3N independently decides it.</p>
    </section>
  );
}
