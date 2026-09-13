import { BadgeCheck, KeyRound, RefreshCw, Server, Shield, ShieldCheck, UserRoundCog } from 'lucide-react';
import type { AgentRegistrationState, DelegationState, EffectiveDelegationState, SystemStatus } from '../../services/privacyGuardApi';

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

function delegationPillState(state?: DelegationState): PillState {
  if (state === 'ACTIVE') return 'ok';
  if (state === 'SCHEDULED') return 'pending';
  return 'off';
}

function delegationLabel(state?: DelegationState): string {
  if (state === 'SCHEDULED') return 'Scheduled';
  return state ?? 'UNKNOWN';
}

function effectivePillState(state?: EffectiveDelegationState): PillState {
  if (state === 'ACTIVE') return 'ok';
  if (state === 'UNKNOWN') return 'pending';
  return 'off';
}

function effectiveLabel(state?: EffectiveDelegationState): string {
  if (state === 'ACTIVE') return 'Confirmed';
  if (state === 'DENIED') return 'Denied';
  return 'Unknown';
}

export function SystemStatusBar({ status, loading, onRefresh }: Props) {
  const registrationState = status?.agentRegistrationState;
  const ready = Boolean(status?.protectedRemediationReady);
  const evaluationOnly = Boolean(status?.evaluationReady && !status?.protectedRemediationReady);
  const scheduled = status?.delegationState === 'SCHEDULED' || status?.executorDelegationState === 'SCHEDULED';
  const overallState: PillState = loading || scheduled || evaluationOnly ? 'pending' : ready ? 'ok' : 'off';
  const overallLabel = loading
    ? 'Checking live status'
    : ready
      ? 'Operational'
      : evaluationOnly
        ? 'Evaluation ready · execution blocked'
        : scheduled
          ? 'Scheduled'
          : 'Unavailable / incomplete';

  return (
    <section className="status-panel status-panel-secondary" aria-label="Live T3N operational status">
      <div className="status-overview">
        <div>
          <p className="eyebrow">Technical T3N status</p>
          <h2>Live control plane</h2>
          <p>{loading
            ? 'Checking Member Delegations and effective T3N access for the exact functions and scopes used by each principal.'
            : ready
              ? 'Proposal and protected execution use separate authenticated T3N principals, active Member Delegations and independently confirmed effective access.'
              : evaluationOnly
                ? 'Proposal evaluation has effective T3N access, but protected execution is blocked until the Executor is independently confirmed.'
                : scheduled
                  ? 'A Member Delegation exists, but its authorization window has not begun. Protected operations remain unavailable.'
                  : 'One or more T3N controls are unavailable or effective access could not be confirmed. The system fails closed.'}</p>
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
          <div className="status-item"><UserRoundCog aria-hidden="true" /><div><span>Protected executor</span><StatusPill state={status?.executorAuthenticated ? 'ok' : 'off'} label={status?.executorAuthenticated ? 'Authenticated · execute + verify' : status?.executorConfigured ? 'Not authenticated' : 'Not configured'} /></div></div>
          <div className="status-item"><BadgeCheck aria-hidden="true" /><div><span>Agent onboarding</span><StatusPill state={registrationState === 'REGISTERED' ? 'ok' : 'off'} label={registrationLabel(registrationState)} /></div></div>
          <div className="status-item"><Shield aria-hidden="true" /><div><span>Contract</span><StatusPill state={status?.contractResolved ? 'ok' : 'off'} label={status?.contractResolved ? `Resolved · v${status.contractVersion}` : 'Unavailable'} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Proposal member grant</span><StatusPill state={delegationPillState(status?.delegationState)} label={delegationLabel(status?.delegationState)} /></div></div>
          <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Proposal effective T3N access</span><StatusPill state={effectivePillState(status?.delegationEffectiveState)} label={effectiveLabel(status?.delegationEffectiveState)} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Executor member grant</span><StatusPill state={delegationPillState(status?.executorDelegationState)} label={delegationLabel(status?.executorDelegationState)} /></div></div>
          <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Executor effective T3N access</span><StatusPill state={effectivePillState(status?.executorDelegationEffectiveState)} label={effectiveLabel(status?.executorDelegationEffectiveState)} /></div></div>
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
          <div><span>Proposal grant functions</span><code>{status?.delegatedFunctions.length ? status.delegatedFunctions.join(', ') : 'None observed'}</code></div>
          <div><span>Proposal grant scopes</span><code>{status?.delegatedScopes.length ? status.delegatedScopes.join(', ') : 'None observed'}</code></div>
          <div><span>Proposal allowed hosts</span><code>{status?.allowedHosts.length ? status.allowedHosts.join(', ') : 'None'}</code></div>
          <div><span>Proposal checked functions</span><code>{status?.delegationCheckedFunctions.length ? status.delegationCheckedFunctions.join(', ') : 'Not checked'}</code></div>
          <div><span>Proposal checked scopes</span><code>{status?.delegationCheckedScopes.length ? status.delegationCheckedScopes.join(', ') : 'Not checked'}</code></div>
          <div><span>Executor grant functions</span><code>{status?.executorDelegatedFunctions.length ? status.executorDelegatedFunctions.join(', ') : 'None observed'}</code></div>
          <div><span>Executor grant scopes</span><code>{status?.executorDelegatedScopes.length ? status.executorDelegatedScopes.join(', ') : 'None observed'}</code></div>
          <div><span>Executor allowed hosts</span><code>{status?.executorAllowedHosts.length ? status.executorAllowedHosts.join(', ') : 'None observed'}</code></div>
          <div><span>Executor checked functions</span><code>{status?.executorDelegationCheckedFunctions.length ? status.executorDelegationCheckedFunctions.join(', ') : 'Not checked'}</code></div>
          <div><span>Executor checked scopes</span><code>{status?.executorDelegationCheckedScopes.length ? status.executorDelegationCheckedScopes.join(', ') : 'Not checked'}</code></div>
        </div>
      </details>
    </section>
  );
}