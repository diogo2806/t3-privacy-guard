import { ShieldAlert } from 'lucide-react';

export function EmptyState() {
  return (
    <section className="empty-state">
      <ShieldAlert aria-hidden="true" />
      <h2>No scenario result yet</h2>
      <p>Choose an enterprise scenario above, review or edit its synthetic prompt, then ask the agent. The model proposes an action and T3N independently decides the proposal that is actually returned.</p>
    </section>
  );
}
