import { KeyRound, RefreshCw, Server, Shield, UserRoundCog } from 'lucide-react';
import type { SystemStatus } from '../../services/privacyGuardApi';

interface Props { status: SystemStatus | null; loading: boolean; onRefresh: () => void; }

function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return <span className={`status-pill ${ok ? 'status-pill-ok' : 'status-pill-off'}`}>{label}</span>;
}

export function SystemStatusBar({ status, loading, onRefresh }: Props) {
  const delegationActive = status?.delegationState === 'ACTIVE';
  return (
    <section className="status-panel" aria-label="Live T3N operational status">
      <div className="status-grid">
        <div className="status-item"><Server aria-hidden="true" /><div><span>Gateway</span><StatusPill ok={Boolean(status?.gatewayReachable)} label={status?.gatewayReachable ? 'Online' : 'Unavailable'} /></div></div>
        <div className="status-item"><Shield aria-hidden="true" /><div><span>Tenant</span><StatusPill ok={Boolean(status?.tenantAuthenticated)} label={status?.tenantAuthenticated ? `Authenticated · ${status.network ?? 'network'}` : 'Not authenticated'} /></div></div>
        <div className="status-item"><UserRoundCog aria-hidden="true" /><div><span>Agent</span><StatusPill ok={Boolean(status?.agentAuthenticated)} label={status?.agentAuthenticated ? 'Authenticated' : status?.agentConfigured ? 'Not authenticated' : 'Not configured'} /></div></div>
        <div className="status-item"><Shield aria-hidden="true" /><div><span>Contract</span><StatusPill ok={Boolean(status?.contractResolved)} label={status?.contractResolved ? `Resolved · v${status.contractVersion}` : 'Unavailable'} /></div></div>
        <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Delegation</span><StatusPill ok={delegationActive} label={status?.delegationState ?? 'UNKNOWN'} /></div></div>
      </div>
      <div className="status-meta">
        <div><span>Tenant DID</span><code>{status?.tenantDid ?? 'Unavailable'}</code></div>
        <div><span>Agent DID</span><code>{status?.agentDid ?? 'Unavailable'}</code></div>
        <div><span>Contract</span><code>{status?.contractId ?? 'Unavailable'}</code></div>
        <div><span>Delegated functions</span><code>{status?.delegatedFunctions.length ? status.delegatedFunctions.join(', ') : 'None observed'}</code></div>
        <div><span>Allowed hosts</span><code>{status?.allowedHosts.length ? status.allowedHosts.join(', ') : 'None observed'}</code></div>
      </div>
      <div className="status-footer">
        <p>{status?.message ?? 'Loading live operational status…'}</p>
        <button className="button button-ghost" type="button" onClick={onRefresh} disabled={loading}><RefreshCw aria-hidden="true" />{loading ? 'Refreshing…' : 'Refresh status'}</button>
      </div>
    </section>
  );
}
