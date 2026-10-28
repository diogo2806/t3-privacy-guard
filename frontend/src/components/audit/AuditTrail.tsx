import { useCallback, useEffect, useState } from 'react';
import { FileClock, Network, RefreshCw } from 'lucide-react';
import { privacyGuardApi, type AuditEvent, type AuditEvidence, type AuditReconciliationStatus, type LocalAuditEvidence } from '../../services/privacyGuardApi';
import { AuditIntegrityStatus } from './AuditIntegrityStatus';

function statusLabel(status: AuditReconciliationStatus, runtimeAvailable: boolean) {
  if (!runtimeAvailable && status === 'UNMATCHED') return 'Runtime unavailable';
  if (status === 'LOCAL_ONLY') return 'Local only';
  if (status === 'RUNTIME_ONLY') return 'Runtime only';
  if (status === 'MATCHED') return 'Matched';
  return 'Unmatched';
}

function statusClass(status: AuditReconciliationStatus, runtimeAvailable: boolean) {
  if (!runtimeAvailable && status === 'UNMATCHED') return 'audit-status-unavailable';
  return `audit-status-${status.toLowerCase().replace('_', '-')}`;
}

function eventTypeLabel(type: string): string {
  if (type === 'REMEDIATION_AUTHORIZED') return 'HUMAN AUTHORIZATION';
  return type.replaceAll('_', ' ');
}

function isLocalAuditEvidence(event: AuditEvent): event is LocalAuditEvidence {
  return 'status' in event;
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
      setError(cause instanceof Error ? cause.message : 'Audit evidence could not be loaded. Local events remain visible, but integrity and Guard runtime provenance were not verified.');
    } finally { setLoading(false); }
  }, [incidentId]);

  useEffect(() => { void refresh(); }, [refresh, auditVersion]);

  const runtimeAvailable = evidence?.provenance.runtimeAvailable ?? false;
  return (
    <section className="card audit-card" aria-labelledby="audit-provenance-title">
      <div className="card-heading">
        <div className="section-icon"><FileClock aria-hidden="true" /></div>
        <div><p className="eyebrow">Audit evidence</p><h2 id="audit-provenance-title">Local integrity + Guard runtime provenance</h2></div>
        <button type="button" className="button button-secondary audit-refresh" onClick={() => void refresh()} disabled={loading || !incidentId}>
          <RefreshCw aria-hidden="true" /><span>{loading ? 'Refreshing…' : 'Refresh audit evidence'}</span>
        </button>
      </div>
      <p className="card-copy">Local HMAC integrity and Guard runtime activity provenance are independent signals. A Guard runtime match still requires exact sequence, hash, contract, function and its canonical actor: Proposal Agent for evaluation, Protected Executor for execution and verification.</p>

      {error && <div className="audit-provenance-note audit-provenance-note-error" role="alert">{error}</div>}
      {loading && !evidence && <p className="empty-copy" role="status">Checking local integrity and runtime provenance. Stored business events remain visible below.</p>}

      {evidence && <>
        <AuditIntegrityStatus integrity={evidence.integrity} />
        <div className={`audit-provenance-note ${evidence.provenance.runtimeAvailable ? '' : 'audit-provenance-note-warning'}`} role={evidence.provenance.runtimeAvailable ? 'status' : 'alert'}>
          {evidence.provenance.message}
        </div>
        <div className="audit-summary-grid" aria-label="Audit reconciliation summary">
          <div><span>Matched</span><strong>{evidence.provenance.matched}</strong></div>
          <div><span>Unmatched</span><strong>{evidence.provenance.unmatched}</strong></div>
          <div><span>Local only</span><strong>{evidence.provenance.localOnly}</strong></div>
          <div><span>Runtime only</span><strong>{evidence.provenance.runtimeOnly}</strong></div>
        </div>
      </>}

      <section className="audit-source" aria-labelledby="local-audit-title">
        <div className="audit-source-heading"><FileClock aria-hidden="true" /><div><h3 id="local-audit-title">Sanitized business audit</h3><p>Application events persisted by the incident workflow. Integrity is reported separately above.</p></div></div>
        {(evidence?.localEvents ?? events).length === 0 ? <p className="empty-copy">No business audit events yet.</p> : (
          <ol className="audit-list">
            {(evidence?.localEvents ?? events).map((event) => {
              const reconciled = isLocalAuditEvidence(event) ? event : null;
              return <li key={event.id}>
                <span className="audit-dot" />
                <div className="audit-event-body">
                  <div className="audit-event-title">
                    <strong>{eventTypeLabel(event.type)}</strong>
                    {reconciled && <span className={`audit-status ${statusClass(reconciled.status, runtimeAvailable)}`}>{statusLabel(reconciled.status, runtimeAvailable)}</span>}
                  </div>
                  <p>{event.message}</p>
                  {reconciled?.runtimeFunction && <small>Expected Guard runtime function: <code>{reconciled.runtimeFunction}</code>{reconciled.matchedSequence != null ? ` · sequence ${reconciled.matchedSequence}` : ''}</small>}
                  <time>{new Date(event.createdAt).toLocaleString()}</time>
                </div>
              </li>;
            })}
          </ol>
        )}
      </section>

      <section className="audit-source" aria-labelledby="runtime-activity-title">
        <div className="audit-source-heading"><Network aria-hidden="true" /><div><h3 id="runtime-activity-title">Guard runtime Activity Log</h3><p>Independent sanitized entries from the hash-chained runtime activity log for this incident window, canonical contract and function-specific actor boundary.</p></div></div>
        {!evidence ? <p className="empty-copy">Runtime provenance has not been loaded yet.</p> : !evidence.provenance.runtimeAvailable ? <p className="empty-copy">Runtime provenance was not verified. This does not change the separately reported local integrity state.</p> : evidence.runtimeEvents.length === 0 ? (
          <p className="empty-copy">No relevant Guard runtime operations were observed in this bounded incident window.</p>
        ) : (
          <ol className="audit-list audit-list-network">
            {evidence.runtimeEvents.map((event) => <li key={event.sequence}>
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
        {evidence?.provenance.runtimeAvailable && !evidence.provenance.runtimeComplete && <p className="audit-window-note">The configured limit of {evidence.limit} events was reached. This view is intentionally bounded; unmatched items are not proof of absence.</p>}
      </section>
    </section>
  );
}
