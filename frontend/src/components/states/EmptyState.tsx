import { ShieldAlert } from 'lucide-react';
import { useTrustRuntime } from '../../services/trustRuntime';

export function EmptyState() {
  const runtimeName = useTrustRuntime().name;
  return (
    <section className="empty-state" aria-labelledby="empty-state-title">
      <ShieldAlert aria-hidden="true" />
      <h2 id="empty-state-title">No scenario result yet</h2>
      <p>Choose an enterprise scenario, review or edit its synthetic prompt, then use Ask agent. Scenario selection alone never calls an API, authorizes an action or predicts the {runtimeName} policy decision.</p>
    </section>
  );
}
