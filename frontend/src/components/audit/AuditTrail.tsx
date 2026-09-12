import { FileClock } from 'lucide-react';
import type { AuditEvent } from '../../services/privacyGuardApi';

export function AuditTrail({ events }: { events: AuditEvent[] }) {
  return (
    <section className="card audit-card">
      <div className="card-heading compact"><div className="section-icon"><FileClock aria-hidden="true" /></div><div><p className="eyebrow">Sanitized audit</p><h2>Decision trail</h2></div></div>
      {events.length === 0 ? <p className="empty-copy">No audit events yet.</p> : <ol className="audit-list">{events.map((event) => <li key={event.id}><span className="audit-dot" /><div><strong>{event.type.replaceAll('_', ' ')}</strong><p>{event.message}</p><time>{new Date(event.createdAt).toLocaleString()}</time></div></li>)}</ol>}
    </section>
  );
}
