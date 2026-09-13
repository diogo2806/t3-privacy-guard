import { BadgeCheck, KeyRound, RefreshCw, Server, Shield, UserRoundCog } from 'lucide-react';
import type { AgentRegistrationState, SystemStatus } from '../../services/privacyGuardApi';

interface Props { status: SystemStatus | null; loading: boolean; onRefresh: () => void; }
type PillState = 'ok' | 'off' | 'pending';

function StatusPill({ state, label }: { state: PillState; label: string }) {
  return <span className={`status-pill status-pill-${state}`}>{label}</span>;
}

function registrationLabel(state?: AgentRegistrationState): string {
  if (state === 'REGISTERED') return 'Registered';
  if (state === 'NOT_REGISTERED') return 'Not registered';
  if (state === 'MISMATCH') return 'Card/DID mismatch';
  return 'Unavailable';
}

function isReady(status: SystemStatus | null): boolean {
  return Boolean(
    status?.gatewayReachable
      && status.tenantAuthenticated
      && status.agentAuthenticated
      && status.contractResolved
      && status.delegationState === 'ACTIVE',
  );
}

export function SystemStatusBar({ status, loading, onRefresh }: Props) {
  const delegationActive = status?.delegationState === 'ACTIVE';
  const registrationState = status?.agentRegistrationState;
  const ready = isReady(status);
  const overallState: PillState = loading ? 'pending' : ready ? 'ok' : 'off';
  const overallLabel = loading ? 'Checking live status' : ready ? 'Operational' : 'Unavailable / incomplete';

  return (
    <section className="status-panel status-panel-secondary" aria-label="Live T3N operational status">
      <div className="status-overview">
        <div>
          <p className="eyebrow">Technical T3N status</p>
          <h2>Live control plane</h2>
          <p>{loading ? 'Checking the controls used to evaluate and execute protected actions.' : ready ? 'Policy and protected execution controls are available.' : 'One or more T3N controls are unavailable. Decisions or execution may not be provable.'}</p>
        </div>
        <StatusPill state={overallState} label={overallLabel} />
      </div>

      <div className="status-footer">
        <p>{status?.message ?? 'Live operational details have not been loaded yet.'}</p>
        <button className="button button-ghost" type="button" onClick={onRefresh} disabled={loading}><RefreshCw aria-hidden="true" />{loading ? 'Refreshing…' : 'Refresh status'}</button>
      </div>

      <details className="status-details">
        <summary>Show technical details</summary>
        <div className="status-grid">
          <div className="status-item"><Server aria-hidden="true" /><div><span>Gateway</span><StatusPill state={status?.gatewayReachable ? 'ok' : 'off'} label={status?.gatewayReachable ? 'Online' : 'Unavailable'} /></div></div>
          <div className="status-item"><Shield aria-hidden="true" /><div><span>Tenant</span><StatusPill state={status?.tenantAuthenticated ? 'ok' : 'off'} label={status?.tenantAuthenticated ? `Authenticated · ${status.network ?? 'network'}` : 'Not authenticated'} /></div></div>
          <div className="status-item"><UserRoundCog aria-hidden="true" /><div><span>Agent</span><StatusPill state={status?.agentAuthenticated ? 'ok' : 'off'} label={status?.agentAuthenticated ? 'Authenticated' : status?.agentConfigured ? 'Not authenticated' : 'Not configured'} /></div></div>
          <div className="status-item"><BadgeCheck aria-hidden="true" /><div><span>Agent onboarding</span><StatusPill state={registrationState === 'REGISTERED' ? 'ok' : 'off'} label={registrationLabel(registrationState)} /></div></div>
          <div className="status-item"><Shield aria-hidden="true" /><div><span>Contract</span><StatusPill state={status?.contractResolved ? 'ok' : 'off'} label={status?.contractResolved ? `Resolved · v${status.contractVersion}` : 'Unavailable'} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Delegation</span><StatusPill state={delegationActive ? 'ok' : 'off'} label={status?.delegationState ?? 'UNKNOWN'} /></div></div>
        </div>
        <div className="status-meta">
          <div><span>Tenant DID</span><code>{status?.tenantDid ?? 'Unavailable'}</code></div>
          <div><span>Agent DID</span><code>{status?.agentDid ?? 'Unavailable'}</code></div>
          <div><span>Public Agent Card</span><code>{status?.agentCardUri ?? 'Not resolved'}</code></div>
          <div><span>Agent Card SHA-256</span><code>{status?.agentCardSha256 ?? 'Not available'}</code></div>
          <div><span>Agent Card services</span><code>{status?.agentCardServices?.length ? status.agentCardServices.join(', ') : 'None verified'}</code></div>
          <div><span>Card verified</span><code>{status?.agentCardVerifiedAt ? new Date(status.agentCardVerifiedAt).toLocaleString() : 'Not available'}</code></div>
          <div><span>Contract</span><code>{status?.contractId ?? 'Unavailable'}</code></div>
          <div><span>Delegated functions</span><code>{status?.delegatedFunctions.length ? status.delegatedFunctions.join(', ') : 'None observed'}</code></div>
          <div><span>Allowed hosts</span><code>{status?.allowedHosts.length ? status.allowedHosts.join(', ') : 'None observed'}</code></div>
        </div>
      </details>
    </section>
  );
}
