import { AlertTriangle } from 'lucide-react';
import type { Incident } from '../../services/privacyGuardApi';

export function IncidentSummary({ incident }: { incident: Incident }) {
  return (
    <section className="card incident-card">
      <div className="card-heading">
        <div className="section-icon section-icon-danger"><AlertTriangle aria-hidden="true" /></div>
        <div><p className="eyebrow">Current incident</p><h2>{incident.title}</h2></div>
        <span className="severity-badge">{incident.severity}</span>
      </div>
      <p className="card-copy">{incident.summary}</p>
      <dl className="detail-grid"><div><dt>Incident ID</dt><dd><code>{incident.id}</code></dd></div><div><dt>Source</dt><dd>{incident.source}</dd></div><div><dt>Status</dt><dd>{incident.status}</dd></div><div><dt>Created</dt><dd>{new Date(incident.createdAt).toLocaleString()}</dd></div></dl>
    </section>
  );
}
