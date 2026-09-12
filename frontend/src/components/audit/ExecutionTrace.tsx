import { Activity } from 'lucide-react';
import type { ActionProposal, ExecutionTraceEvent } from '../../services/privacyGuardApi';

function label(value: string) {
  return value.replaceAll('_', ' ').toLowerCase().replace(/(^|\s)\S/g, (letter) => letter.toUpperCase());
}

export function ExecutionTrace({ events, action }: { events: ExecutionTraceEvent[]; action: ActionProposal | null }) {
  return (
    <section className="card execution-trace-card" aria-labelledby="execution-trace-title">
      <div className="card-heading compact">
        <div className="section-icon"><Activity aria-hidden="true" /></div>
        <div><p className="eyebrow">Technical correlation</p><h2 id="execution-trace-title">Execution trace</h2></div>
      </div>
      {!action ? (
        <p className="empty-copy">Select an action to inspect its technical execution trace.</p>
      ) : (
        <>
          <p className="trace-request">Request <code>{action.requestId}</code></p>
          {events.length === 0 ? <p className="empty-copy">No execution trace has been recorded for this action yet.</p> : (
            <ol className="trace-list">
              {events.map((event) => (
                <li key={event.id} className="trace-item">
                  <div className="trace-item-heading">
                    <strong>{label(event.stage)}</strong>
                    <span className="trace-state" data-state={event.state}>{label(event.state)}</span>
                  </div>
                  <div className="trace-meta">
                    <time dateTime={event.createdAt}>{new Date(event.createdAt).toLocaleString()}</time>
                    {event.durationMs != null && <span>{event.durationMs} ms</span>}
                  </div>
                  {event.reasonCode && <p className="trace-reason">Reason code <code>{event.reasonCode}</code></p>}
                  <p className="trace-id">Trace <code>{event.traceId}</code></p>
                </li>
              ))}
            </ol>
          )}
        </>
      )}
    </section>
  );
}
