import { BadgeCheck, KeyRound, RefreshCw, Server, Shield, UserRoundCog } from 'lucide-react';
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

function memberPillState(state?: DelegationState): PillState {
  if (state === 'ACTIVE') return 'ok';
  if (state === 'SCHEDULED') return 'pending';
  return 'off';
}

function memberLabel(state?: DelegationState): string {
  if (state === 'SCHEDULED') return 'Scheduled';
  if (state === 'NOT_GRANTED') return 'Not granted';
  return state ?? 'UNKNOWN';
}

function effectivePillState(state?: EffectiveDelegationState): PillState {
  return state === 'ACTIVE' ? 'ok' : 'off';
}

function effectiveLabel(state?: EffectiveDelegationState): string {
  if (state === 'ACTIVE') return 'ACTIVE';
  if (state === 'INCOMPLETE') return 'INCOMPLETE';
  return 'UNKNOWN';
}

function platformDelegation(memberState?: DelegationState, effectiveState?: EffectiveDelegationState): { state: PillState; label: string } {
  if (memberState !== 'ACTIVE') {
    return { state: memberState === 'SCHEDULED' ? 'pending' : 'off', label: 'Not checked' };
  }
  if (effectiveState === 'ACTIVE') return { state: 'ok', label: 'Authorized' };
  if (effectiveState === 'INCOMPLETE') return { state: 'off', label: 'Not authorized' };
  return { state: 'off', label: 'Unavailable' };
}

function isReady(status: SystemStatus | null): boolean {
  return Boolean(
    status?.gatewayReachable
      && status.tenantAuthenticated
      && status.agentAuthenticated
      && status.executorAuthenticated
      && status.contractResolved
      && status.delegationEffectiveState === 'ACTIVE'
      && status.executorDelegationEffectiveState === 'ACTIVE',
  );
}

export function SystemStatusBar({ status, loading, onRefresh }: Props) {
  const registrationState = status?.agentRegistrationState;
  const ready = isReady(status);
  const scheduled = status?.delegationMemberState === 'SCHEDULED' || status?.executorDelegationMemberState === 'SCHEDULED';
  const overallState: PillState = loading || scheduled ? 'pending' : ready ? 'ok' : 'off';
  const overallLabel = loading ? 'Checking live status' : ready ? 'Operational' : scheduled ? 'Scheduled' : 'Unavailable / incomplete';
  const proposalPlatform = platformDelegation(status?.delegationMemberState, status?.delegationEffectiveState);
  const executorPlatform = platformDelegation(status?.executorDelegationMemberState, status?.executorDelegationEffectiveState);

  return (
    <section className="status-panel status-panel-secondary" aria-label="Live T3N operational status">
      <div className="status-overview">
        <div>
          <p className="eyebrow">Technical T3N status</p>
          <h2>Live control plane</h2>
          <p>{loading ? 'Checking the controls used to evaluate and execute protected actions.' : ready ? 'T3N confirmed effective least-privilege access for the Proposal Agent and Protected Executor.' : scheduled ? 'A Member grant exists, but its authorization window has not begun. Effective access remains unavailable.' : 'One or more T3N controls are unavailable or not authorized. Member grants alone do not make protected operations ready.'}</p>
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
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Proposal Member grant</span><StatusPill state={memberPillState(status?.delegationMemberState)} label={memberLabel(status?.delegationMemberState)} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Proposal platform delegation</span><StatusPill state={proposalPlatform.state} label={proposalPlatform.label} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Proposal effective access</span><StatusPill state={effectivePillState(status?.delegationEffectiveState)} label={effectiveLabel(status?.delegationEffectiveState)} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Executor Member grant</span><StatusPill state={memberPillState(status?.executorDelegationMemberState)} label={memberLabel(status?.executorDelegationMemberState)} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Executor platform delegation</span><StatusPill state={executorPlatform.state} label={executorPlatform.label} /></div></div>
          <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Executor effective access</span><StatusPill state={effectivePillState(status?.executorDelegationEffectiveState)} label={effectiveLabel(status?.executorDelegationEffectiveState)} /></div></div>
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
          <div><span>Proposal functions</span><code>{status?.delegatedFunctions.length ? status.delegatedFunctions.join(', ') : 'None observed'}</code></div>
          <div><span>Proposal scopes</span><code>{status?.delegatedScopes.length ? status.delegatedScopes.join(', ') : 'None observed'}</code></div>
          <div><span>Proposal allowed hosts</span><code>{status?.allowedHosts.length ? status.allowedHosts.join(', ') : 'None'}</code></div>
          <div><span>Proposal delegation satisfied</span><code>{status?.delegationSatisfied.length ? status.delegationSatisfied.join(', ') : 'None reported'}</code></div>
          <div><span>Proposal delegation missing</span><code>{status?.delegationMissing.length ? status.delegationMissing.join(', ') : 'None reported'}</code></div>
          <div><span>Executor functions</span><code>{status?.executorDelegatedFunctions.length ? status.executorDelegatedFunctions.join(', ') : 'None observed'}</code></div>
          <div><span>Executor scopes</span><code>{status?.executorDelegatedScopes.length ? status.executorDelegatedScopes.join(', ') : 'None observed'}</code></div>
          <div><span>Executor allowed hosts</span><code>{status?.executorAllowedHosts.length ? status.executorAllowedHosts.join(', ') : 'None observed'}</code></div>
          <div><span>Executor delegation satisfied</span><code>{status?.executorDelegationSatisfied.length ? status.executorDelegationSatisfied.join(', ') : 'None reported'}</code></div>
          <div><span>Executor delegation missing</span><code>{status?.executorDelegationMissing.length ? status.executorDelegationMissing.join(', ') : 'None reported'}</code></div>
        </div>
      </details>
    </section>
  );
}
