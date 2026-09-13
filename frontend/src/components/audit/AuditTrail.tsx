import { useCallback, useEffect, useState } from 'react';
import { FileClock, Network, RefreshCw } from 'lucide-react';
import { privacyGuardApi, type AuditEvent, type AuditEvidence, type AuditReconciliationStatus } from '../../services/privacyGuardApi';
import { AuditIntegrityStatus } from './AuditIntegrityStatus';

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

export function AuditTrail({ events }: { events: AuditEvent[] }) {
  const incidentId = events[0]?.incidentId ?? null;
  const auditVersion = events.at(-1)?.id ?? '';
  const [evidence, setEvidence] = useState<AuditEvidence | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!incidentId) { setEvidence(null); return; }
    setLoading(true); setError(null);
    try { setEvidence(await privacyGuardApi.auditEvidence(incidentId)); }
    catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Audit evidence could not be loaded. Local events remain visible, but integrity and T3N provenance were not verified.');
    } finally { setLoading(false); }
  }, [incidentId]);

  useEffect(() => { void refresh(); }, [refresh, auditVersion]);

  const t3nAvailable = evidence?.provenance.t3nAvailable ?? false;
  return (
    <section className="card audit-card" aria-labelledby="audit-provenance-title">
      <div className="card-heading">
        <div className="section-icon"><FileClock aria-hidden="true" /></div>
        <div><p className="eyebrow">Audit evidence</p><h2 id="audit-provenance-title">Local integrity + T3N provenance</h2></div>
        <button type="button" className="button button-secondary audit-refresh" onClick={() => void refresh()} disabled={loading || !incidentId}>
          <RefreshCw aria-hidden="true" /><span>{loading ? 'Refreshing…' : 'Refresh audit evidence'}</span>
        </button>
      </div>
      <p className="card-copy">Local HMAC integrity and T3N network provenance are independent signals. A T3N match still requires exact sequence, hash, contract, function and its canonical actor: Proposal Agent for evaluation, Protected Executor for execution and verification.</p>

      {error && <div className="audit-provenance-note audit-provenance-note-error" role="alert">{error}</div>}
      {loading && !evidence && <p className="empty-copy" role="status">Checking local integrity and network provenance. Stored business events remain visible below.</p>}

      {evidence && <>
        <AuditIntegrityStatus integrity={evidence.integrity} />
        <div className={`audit-provenance-note ${evidence.provenance.t3nAvailable ? '' : 'audit-provenance-note-warning'}`} role={evidence.provenance.t3nAvailable ? 'status' : 'alert'}>
          {evidence.provenance.message}
        </div>
        <div className="audit-summary-grid" aria-label="Audit reconciliation summary">
          <div><span>Matched</span><strong>{evidence.provenance.matched}</strong></div>
          <div><span>Unmatched</span><strong>{evidence.provenance.unmatched}</strong></div>
          <div><span>Local only</span><strong>{evidence.provenance.localOnly}</strong></div>
          <div><span>T3N only</span><strong>{evidence.provenance.t3nOnly}</strong></div>
        </div>
      </>}

      <section className="audit-source" aria-labelledby="local-audit-title">
        <div className="audit-source-heading"><FileClock aria-hidden="true" /><div><h3 id="local-audit-title">Sanitized business audit</h3><p>Application events persisted by the incident workflow. Integrity is reported separately above.</p></div></div>
        {(evidence?.localEvents ?? events).length === 0 ? <p className="empty-copy">No business audit events yet.</p> : (
          <ol className="audit-list">
            {(evidence?.localEvents ?? events).map((event) => {
              const reconciled = 'status' in event ? event : null;
              return <li key={event.id}>
                <span className="audit-dot" />
                <div className="audit-event-body">
                  <div className="audit-event-title">
                    <strong>{event.type.replaceAll('_', ' ')}</strong>
                    {reconciled && <span className={`audit-status ${statusClass(reconciled.status, t3nAvailable)}`}>{statusLabel(reconciled.status, t3nAvailable)}</span>}
                  </div>
                  <p>{event.message}</p>
                  {reconciled?.t3nFunction && <small>Expected T3N function: <code>{reconciled.t3nFunction}</code>{reconciled.matchedSequence != null ? ` · sequence ${reconciled.matchedSequence}` : ''}</small>}
                  <time>{new Date(event.createdAt).toLocaleString()}</time>
                </div>
              </li>;
            })}
          </ol>
        )}
      </section>

      <section className="audit-source" aria-labelledby="t3n-activity-title">
        <div className="audit-source-heading"><Network aria-hidden="true" /><div><h3 id="t3n-activity-title">T3N Activity Log</h3><p>Independent sanitized network metadata for this incident window, canonical contract and function-specific actor boundary.</p></div></div>
        {!evidence ? <p className="empty-copy">Network provenance has not been loaded yet.</p> : !evidence.provenance.t3nAvailable ? <p className="empty-copy">Network provenance was not verified. This does not change the separately reported local integrity state.</p> : evidence.t3nEvents.length === 0 ? (
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
            )}
          </ol>
        )}
        {evidence?.provenance.t3nAvailable && !evidence.provenance.t3nComplete && <p className="audit-window-note">The configured limit of {evidence.limit} events was reached. This view is intentionally bounded; unmatched items are not proof of absence.</p>}
      </section>
    </section>
  );
}
