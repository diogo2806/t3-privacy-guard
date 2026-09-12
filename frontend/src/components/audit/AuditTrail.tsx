import { FileClock, Network, RefreshCw } from 'lucide-react';
import type { AuditEvidence, AuditReconciliationStatus } from '../../services/privacyGuardApi';

interface AuditTrailProps {
  evidence: AuditEvidence | null;
  loading: boolean;
  error: string | null;
  onRefresh: () => void;
}

function statusLabel(status: AuditReconciliationStatus, t3nAvailable: boolean) {
  if (!t3nAvailable && status === 'UNMATCHED') return 'T3N unavailable';
  if (status === 'LOCAL_ONLY') return 'Local only';
  if (status === 'T3N_ONLY') return 'T3N only';
  if (status === 'MATCHED') return 'Matched';
  return 'Unmatched';
}

function statusClass(status: AuditReconciliationStatus, t3nAvailable: boolean) {
  if (!t3nAvailable && status === 'UNMATCHED') return 'audit-status-unavailable';
  return `audit-status-${status.toLowerCase().replace('_', '-')}`;
}

export function AuditTrail({ evidence, loading, error, onRefresh }: AuditTrailProps) {
  const t3nAvailable = evidence?.provenance.t3nAvailable ?? false;
  return (
    <section className="card audit-card" aria-labelledby="audit-provenance-title">
      <div className="card-heading">
        <div className="section-icon"><FileClock aria-hidden="true" /></div>
        <div><p className="eyebrow">Audit provenance</p><h2 id="audit-provenance-title">Local audit + T3N activity</h2></div>
        <button type="button" className="button button-secondary audit-refresh" onClick={onRefresh} disabled={loading}>
          <RefreshCw aria-hidden="true" /><span>{loading ? 'Refreshing…' : 'Refresh provenance'}</span>
        </button>
      </div>
      <p className="card-copy">Business events and independent T3N metadata remain separate. A match requires exact sequence, hash, contract, agent and function identifiers.</p>

      {error && <div className="audit-provenance-note audit-provenance-note-error" role="alert">{error}</div>}
      {loading && !evidence && <p className="empty-copy" role="status">Loading audit provenance…</p>}

      {evidence && <>
        <div className={`audit-provenance-note ${evidence.provenance.t3nAvailable ? '' : 'audit-provenance-note-warning'}`} role={evidence.provenance.t3nAvailable ? 'status' : 'alert'}>
          {evidence.provenance.message}
        </div>
        <div className="audit-summary-grid" aria-label="Audit reconciliation summary">
          <div><span>Matched</span><strong>{evidence.provenance.matched}</strong></div>
          <div><span>Unmatched</span><strong>{evidence.provenance.unmatched}</strong></div>
          <div><span>Local only</span><strong>{evidence.provenance.localOnly}</strong></div>
          <div><span>T3N only</span><strong>{evidence.provenance.t3nOnly}</strong></div>
        </div>

        <section className="audit-source" aria-labelledby="local-audit-title">
          <div className="audit-source-heading"><FileClock aria-hidden="true" /><div><h3 id="local-audit-title">Local business audit</h3><p>Application events persisted by the incident workflow.</p></div></div>
          {evidence.localEvents.length === 0 ? <p className="empty-copy">No local audit events yet.</p> : (
            <ol className="audit-list">
              {evidence.localEvents.map((event) => <li key={event.id}>
                <span className="audit-dot" />
                <div className="audit-event-body">
                  <div className="audit-event-title"><strong>{event.type.replaceAll('_', ' ')}</strong><span className={`audit-status ${statusClass(event.status, t3nAvailable)}`}>{statusLabel(event.status, t3nAvailable)}</span></div>
                  <p>{event.message}</p>
                  {event.t3nFunction && <small>Expected T3N function: <code>{event.t3nFunction}</code>{event.matchedSequence != null ? ` · sequence ${event.matchedSequence}` : ''}</small>}
                  <time>{new Date(event.createdAt).toLocaleString()}</time>
                </div>
              </li>)}
            </ol>
          )}
        </section>

        <section className="audit-source" aria-labelledby="t3n-activity-title">
          <div className="audit-source-heading"><Network aria-hidden="true" /><div><h3 id="t3n-activity-title">T3N Activity Log</h3><p>Sanitized network metadata for this incident window and canonical contract identity.</p></div></div>
          {!evidence.provenance.t3nAvailable ? <p className="empty-copy">Network provenance was not verified. The local business audit above remains available.</p> : evidence.t3nEvents.length === 0 ? (
            <p className="empty-copy">No relevant T3N operations were observed in this bounded incident window.</p>
          ) : (
            <ol className="audit-list audit-list-network">
              {evidence.t3nEvents.map((event) => <li key={event.sequence}>
                <span className="audit-dot audit-dot-network" />
                <div className="audit-event-body">
                  <div className="audit-event-title"><strong>{event.function}</strong><span className={`audit-status ${statusClass(event.status, true)}`}>{statusLabel(event.status, true)}</span></div>
                  <p>Sequence {event.sequence} · {event.outcome}</p>
                  <small>Actor <code>{event.actorDid}</code></small>
                  <small>Contract <code>{event.contractId}</code></small>
                  <small>Hash <code>{event.hash}</code></small>
                  <time>{new Date(event.timestamp).toLocaleString()}</time>
                </div>
              </li>)}
            </ol>
          )}
          {evidence.provenance.t3nAvailable && !evidence.provenance.t3nComplete && <p className="audit-window-note">The configured limit of {evidence.limit} events was reached. This view is intentionally bounded; unmatched items are not proof of absence.</p>}
        </section>
      </>}
    </section>
  );
}
