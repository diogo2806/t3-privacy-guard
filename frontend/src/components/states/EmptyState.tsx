import { ShieldAlert } from 'lucide-react';

export function EmptyState() {
  return (
    <section className="empty-state" aria-labelledby="empty-state-title">
      <ShieldAlert aria-hidden="true" />
      <h2 id="empty-state-title">No scenario result yet</h2>
      <p>Choose an enterprise scenario, review or edit its synthetic prompt, then use Ask agent. Scenario selection alone never calls an API, authorizes an action or predicts the T3N policy decision.</p>
    </section>
  );
}
