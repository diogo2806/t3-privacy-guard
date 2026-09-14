import { AlertTriangle, Clock } from 'lucide-react';
import type { Incident } from '../../services/privacyGuardApi';
import { SectionHeader } from '../ui/SectionHeader';
import { StatusBadge, type StatusBadgeTone } from '../ui/StatusBadge';
import { Surface } from '../ui/Surface';

export function IncidentSummary({ incident }: { incident: Incident }) {
  const expiresAt = new Date(incident.expiresAt).toLocaleString();
  const severityTone = incident.severity.toLowerCase() as StatusBadgeTone;

  return (
    <Surface className="incident-card">
      <SectionHeader eyebrow="Incident" title={incident.title} icon={<AlertTriangle aria-hidden="true" />} tone="danger" compact={false} trailing={<StatusBadge tone={severityTone}>{incident.severity}</StatusBadge>} />
      <p className="card-copy">{incident.summary}</p>
      <dl className="detail-grid"><div><dt>Incident ID</dt><dd><code>{incident.id}</code></dd></div><div><dt>Source</dt><dd>{incident.source}</dd></div><div><dt>Status</dt><dd>{incident.status}</dd></div><div><dt>Received at</dt><dd>{new Date(incident.createdAt).toLocaleString()}</dd></div></dl>
      <div className="retention-panel" aria-label="Data retention">
        <div className="retention-heading">
          <div className="section-icon"><Clock aria-hidden="true" /></div>
          <div><p className="eyebrow">Data retention</p><strong>Expires automatically on {expiresAt}</strong></div>
        </div>
        <p className="retention-copy">Sensitive values are rejected before local storage. Accepted text is normalized and minimized; it is not anonymous data.</p>
      </div>
    </Surface>
  );
}
