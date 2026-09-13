import { AlertTriangle, Clock } from 'lucide-react';
import type { Incident } from '../../services/privacyGuardApi';

export function IncidentSummary({ incident }: { incident: Incident }) {
  const expiresAt = new Date(incident.expiresAt).toLocaleString();

  return (
    <section className="card incident-card">
      <div className="card-heading">
        <div className="section-icon section-icon-danger"><AlertTriangle aria-hidden="true" /></div>
        <div><p className="eyebrow">Incident</p><h2>{incident.title}</h2></div>
        <span className={`severity-badge severity-badge-${incident.severity.toLowerCase()}`}>{incident.severity}</span>
      </div>
      <p className="card-copy">{incident.summary}</p>
      <dl className="detail-grid"><div><dt>Incident ID</dt><dd><code>{incident.id}</code></dd></div><div><dt>Source</dt><dd>{incident.source}</dd></div><div><dt>Status</dt><dd>{incident.status}</dd></div><div><dt>Created</dt><dd>{new Date(incident.createdAt).toLocaleString()}</dd></div></dl>
      <div className="retention-panel" aria-label="Data retention">
        <div className="retention-heading">
          <div className="section-icon"><Clock aria-hidden="true" /></div>
          <div><p className="eyebrow">Data retention</p><strong>Expires automatically on {expiresAt}</strong></div>
        </div>
        <p className="retention-copy">Sensitive values are rejected before local storage. Accepted text is normalized and minimized; it is not anonymous data.</p>
      </div>
    </section>
  );
}
