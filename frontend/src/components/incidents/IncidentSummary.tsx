import { AlertTriangle, Clock } from 'lucide-react';
import type { Incident } from '../../services/privacyGuardApi';

export function IncidentSummary({ incident }: { incident: Incident }) {
  const expiresAt = new Date(incident.expiresAt).toLocaleString();

  return (
    <section className="card incident-card">
      <div className="card-heading">
        <div className="icon-tile"><AlertTriangle aria-hidden="true" /></div>
        <div><p className="eyebrow">Incident</p><h2>{incident.title}</h2></div>
        <span className={`severity severity-${incident.severity.toLowerCase()}`}>{incident.severity}</span>
      </div>
      <p className="card-copy">{incident.summary}</p>
      <dl className="detail-grid"><div><dt>Incident ID</dt><dd><code>{incident.id}</code></dd></div><div><dt>Source</dt><dd>{incident.source}</dd></div><div><dt>Status</dt><dd>{incident.status}</dd></div><div><dt>Created</dt><dd>{new Date(incident.createdAt).toLocaleString()}</dd></div></dl>
      <div className="retention-panel" aria-label="Data retention">
        <div className="retention-heading"><Clock aria-hidden="true" /><div><p className="eyebrow">Data retention</p><strong>This incident data expires automatically on {expiresAt}.</strong></div></div>
        <p className="retention-copy">Recognizable sensitive values are rejected before local storage. Accepted incident text is normalized and minimized; it is not anonymous data.</p>
      </div>
    </section>
  );
}
