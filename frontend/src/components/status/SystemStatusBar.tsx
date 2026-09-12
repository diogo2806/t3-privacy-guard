import { RefreshCw, Server, Shield, UserRoundCog } from 'lucide-react';
import type { SystemStatus } from '../../services/privacyGuardApi';

interface Props { status: SystemStatus | null; loading: boolean; onRefresh: () => void; }

function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return <span className={`status-pill ${ok ? 'status-pill-ok' : 'status-pill-off'}`}>{label}</span>;
}

export function SystemStatusBar({ status, loading, onRefresh }: Props) {
  return (
    <section className="status-panel" aria-label="Live T3N status">
      <div className="status-grid">
        <div className="status-item"><Server aria-hidden="true" /><div><span>Gateway</span><StatusPill ok={Boolean(status?.gatewayReachable)} label={status?.gatewayReachable ? 'Online' : 'Unavailable'} /></div></div>
        <div className="status-item"><Shield aria-hidden="true" /><div><span>T3N session</span><StatusPill ok={Boolean(status?.t3nReady)} label={status?.t3nReady ? `Ready · ${status.network ?? 'network'}` : 'Not ready'} /></div></div>
        <div className="status-item"><UserRoundCog aria-hidden="true" /><div><span>Agent</span><StatusPill ok={Boolean(status?.agentReady)} label={status?.agentReady ? 'Authenticated' : status?.agentConfigured ? 'Not ready' : 'Not configured'} /></div></div>
        <div className="status-item"><Shield aria-hidden="true" /><div><span>TEE contract</span><StatusPill ok={Boolean(status?.contractRegistered)} label={status?.contractRegistered ? `Registered · v${status.contractVersion}` : 'Unavailable'} /></div></div>
      </div>
      <div className="status-meta">
        <div><span>Tenant DID</span><code>{status?.tenantDid ?? 'Unavailable'}</code></div>
        <div><span>Agent DID</span><code>{status?.agentDid ?? 'Unavailable'}</code></div>
        <div><span>Contract</span><code>{status?.contractId ?? 'Unavailable'}</code></div>
      </div>
      <div className="status-footer">
        <p>{status?.message ?? 'Loading live capability status…'}</p>
        <button className="button button-ghost" type="button" onClick={onRefresh} disabled={loading}><RefreshCw aria-hidden="true" />{loading ? 'Refreshing…' : 'Refresh status'}</button>
      </div>
    </section>
  );
}
