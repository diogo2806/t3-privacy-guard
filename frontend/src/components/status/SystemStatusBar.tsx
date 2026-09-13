import { BadgeCheck, KeyRound, RefreshCw, Server, Shield, ShieldCheck, UserRoundCog } from 'lucide-react';
import type {
  AgentRegistrationState,
  DelegationState,
  EffectiveDelegationState,
  SystemStatus,
} from '../../services/privacyGuardApi';

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

function memberPillState(state?: DelegationState): PillState {
  if (state === 'ACTIVE') return 'ok';
  if (state === 'SCHEDULED') return 'pending';
  return 'off';
}

function memberLabel(state?: DelegationState): string {
  if (state === 'ACTIVE') return 'Active';
  if (state === 'SCHEDULED') return 'Scheduled';
  if (state === 'REVOKED') return 'Revoked';
  if (state === 'NOT_GRANTED') return 'Not granted';
  return 'Unknown';
}

function effectiveLabel(state?: EffectiveDelegationState): string {
  if (state === 'ACTIVE') return 'Confirmed';
  if (state === 'DENIED') return 'Denied';
  return 'Unknown';
}

function effectivePillState(state?: EffectiveDelegationState): PillState {
  return state === 'ACTIVE' ? 'ok' : 'off';
}

export function SystemStatusBar({ status, loading, onRefresh }: Props) {
  const registrationState = status?.agentRegistrationState;
  const ready = Boolean(status?.protectedRemediationReady);
  const scheduled = status?.proposalMemberState === 'SCHEDULED' || status?.executorMemberState === 'SCHEDULED';
  const overallState: PillState = loading || scheduled ? 'pending' : ready ? 'ok' : 'off';
  const overallLabel = loading ? 'Checking live status' : ready ? 'Operational' : scheduled ? 'Scheduled' : 'Unavailable / incomplete';

  return (
    <section className="status-panel status-panel-secondary" aria-label="Live T3N operational status">
      <div className="status-overview">
        <div>
          <p className="eyebrow">Technical T3N authorization</p>
          <h2>Live control plane</h2>
          <p>{loading
            ? 'Checking authenticated principals, configured Member grants and effective T3N authorization.'
            : ready
              ? 'Member grants are active and T3N has confirmed effective access independently for the Proposal Agent and Protected Executor.'
              : scheduled
                ? 'A Member grant exists, but its authorization window has not begun. Effective access is not considered confirmed.'
                : 'A configured Member grant is not sufficient for readiness. Protected operations remain unavailable until T3N confirms effective access.'}</p>
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
          <div className="status-item"><UserRoundCog aria-hidden="true" /><div><span>Proposal agent</span><StatusPill state={status?.agentAuthenticated ? 'ok' : 'off'} label={status?.agentAuthenticated ? 'Authenticated · evaluate only' : status?.agentConfigured ? 'Not authenticated' : 'Not configured'} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Proposal member grant</span><StatusPill state={memberPillState(status?.proposalMemberState)} label={memberLabel(status?.proposalMemberState)} /></div></div>
          <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Proposal effective T3N access</span><StatusPill state={effectivePillState(status?.proposalEffectiveState)} label={effectiveLabel(status?.proposalEffectiveState)} /></div></div>
          <div className="status-item"><UserRoundCog aria-hidden="true" /><div><span>Protected executor</span><StatusPill state={status?.executorAuthenticated ? 'ok' : 'off'} label={status?.executorAuthenticated ? 'Authenticated · execute + verify' : status?.executorConfigured ? 'Not authenticated' : 'Not configured'} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Executor member grant</span><StatusPill state={memberPillState(status?.executorMemberState)} label={memberLabel(status?.executorMemberState)} /></div></div>
          <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Executor effective T3N access</span><StatusPill state={effectivePillState(status?.executorEffectiveState)} label={effectiveLabel(status?.executorEffectiveState)} /></div></div>
          <div className="status-item"><Shield aria-hidden="true" /><div><span>Contract</span><StatusPill state={status?.contractResolved ? 'ok' : 'off'} label={status?.contractResolved ? `Resolved · v${status.contractVersion}` : 'Unavailable'} /></div></div>
          <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Proposal evaluation</span><StatusPill state={status?.evaluationReady ? 'ok' : 'off'} label={status?.evaluationReady ? 'Ready' : 'Not ready'} /></div></div>
          <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Protected remediation</span><StatusPill state={status?.protectedRemediationReady ? 'ok' : 'off'} label={status?.protectedRemediationReady ? 'Ready' : 'Not ready'} /></div></div>
          <div className="status-item"><BadgeCheck aria-hidden="true" /><div><span>Agent onboarding</span><StatusPill state={registrationState === 'REGISTERED' ? 'ok' : 'off'} label={registrationLabel(registrationState)} /></div></div>
        </div>
        <div className="status-meta">
          <div><span>Tenant DID</span><code>{status?.tenantDid ?? 'Unavailable'}</code></div>
          <div><span>Proposal Agent DID</span><code>{status?.agentDid ?? 'Unavailable'}</code></div>
          <div><span>Protected Executor DID</span><code>{status?.executorDid ?? 'Unavailable'}</code></div>
          <div><span>Public Agent Card</span><code>{status?.agentCardUri ?? 'Not resolved'}</code></div>
          <div><span>Agent Card SHA-256</span><code>{status?.agentCardSha256 ?? 'Not available'}</code></div>
          <div><span>Agent Card services</span><code>{status?.agentCardServices?.length ? status.agentCardServices.join(', ') : 'None verified'}</code></div>
          <div><span>Card check</span><code>{status?.agentCardVerifiedAt ? new Date(status.agentCardVerifiedAt).toLocaleString() : 'Not available'}</code></div>
          <div><span>Contract</span><code>{status?.contractId ?? 'Unavailable'}</code></div>
          <div><span>Proposal grant functions</span><code>{status?.proposalDelegatedFunctions.length ? status.proposalDelegatedFunctions.join(', ') : 'None observed'}</code></div>
          <div><span>Proposal grant scopes</span><code>{status?.proposalDelegatedScopes.length ? status.proposalDelegatedScopes.join(', ') : 'None observed'}</code></div>
          <div><span>Proposal checked functions</span><code>{status?.proposalCheckedFunctions.length ? status.proposalCheckedFunctions.join(', ') : 'Not checked'}</code></div>
          <div><span>Proposal checked scopes</span><code>{status?.proposalCheckedScopes.length ? status.proposalCheckedScopes.join(', ') : 'Not checked'}</code></div>
          <div><span>Proposal allowed hosts</span><code>{status?.proposalAllowedHosts.length ? status.proposalAllowedHosts.join(', ') : 'None'}</code></div>
          <div><span>Executor grant functions</span><code>{status?.executorDelegatedFunctions.length ? status.executorDelegatedFunctions.join(', ') : 'None observed'}</code></div>
          <div><span>Executor grant scopes</span><code>{status?.executorDelegatedScopes.length ? status.executorDelegatedScopes.join(', ') : 'None observed'}</code></div>
          <div><span>Executor checked functions</span><code>{status?.executorCheckedFunctions.length ? status.executorCheckedFunctions.join(', ') : 'Not checked'}</code></div>
          <div><span>Executor checked scopes</span><code>{status?.executorCheckedScopes.length ? status.executorCheckedScopes.join(', ') : 'Not checked'}</code></div>
          <div><span>Executor allowed hosts</span><code>{status?.executorAllowedHosts.length ? status.executorAllowedHosts.join(', ') : 'None observed'}</code></div>
        </div>
      </details>
    </section>
  );
}
