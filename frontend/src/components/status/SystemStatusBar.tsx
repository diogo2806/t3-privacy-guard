import { KeyRound, RefreshCw, Server, Shield, UserRoundCog } from 'lucide-react';
import type { DelegationState, EffectiveDelegationState, SystemStatus } from '../../services/privacyGuardApi';
import { EnterpriseIntegrationStatus } from '../integration/EnterpriseIntegrationStatus';
import { StatusPill, type PillState } from './StatusPill';

interface Props { status: SystemStatus | null; loading: boolean; onRefresh: () => void; }

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
  if (state === 'ACTIVE') return 'Confirmed';
  if (state === 'DENIED') return 'Denied';
  return 'Unknown';
}

export function SystemStatusBar({ status, loading, onRefresh }: Props) {
  const runtimeReady = Boolean(status?.protectedRemediationReady);
  const evaluationOnly = Boolean(status?.evaluationReady && !status.protectedRemediationReady);
  const scheduled = status?.delegationMemberState === 'SCHEDULED' || status?.executorDelegationMemberState === 'SCHEDULED';
  const overallState: PillState = loading || scheduled ? 'pending' : runtimeReady ? 'ok' : evaluationOnly ? 'pending' : 'off';
  const overallLabel = loading
    ? 'Checking Guard runtime controls'
    : runtimeReady
      ? 'Guard runtime controls ready'
      : evaluationOnly
        ? 'Evaluation ready · execution blocked'
        : scheduled
          ? 'Scheduled'
          : 'Guard runtime controls incomplete';

  return (
    <>
      <section className="status-panel status-panel-secondary" aria-label="Live Guard runtime operational status">
        <div className="status-overview">
          <div>
            <p className="eyebrow">Technical Guard runtime authorization</p>
            <h2>Live runtime controls</h2>
            <p>{loading
              ? 'Checking the controls used to evaluate and execute protected actions.'
              : runtimeReady
                ? 'Guard runtime confirmed the exact function grants required for Proposal evaluation and Protected Executor remediation.'
                : evaluationOnly
                  ? 'Proposal evaluation is effectively authorized, but protected remediation is not ready.'
                  : scheduled
                    ? 'A function grant exists, but its authorization window has not begun. Effective access remains unavailable.'
                    : 'One or more Guard runtime controls are unavailable or denied. A function grant alone never makes an operation ready.'}</p>
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
            <div className="status-item"><Server aria-hidden="true" /><div><span>Guard runtime</span><StatusPill state={status?.runtimeReachable ? 'ok' : 'off'} label={status?.runtimeReachable ? 'Online' : 'Unavailable'} /></div></div>
            <div className="status-item"><Shield aria-hidden="true" /><div><span>Tenant</span><StatusPill state={status?.tenantAuthenticated ? 'ok' : 'off'} label={status?.tenantAuthenticated ? `Authenticated · ${status.network ?? 'network'}` : 'Not authenticated'} /></div></div>
            <div className="status-item"><UserRoundCog aria-hidden="true" /><div><span>Proposal agent</span><StatusPill state={status?.agentAuthenticated ? 'ok' : 'off'} label={status?.agentAuthenticated ? 'Authenticated · evaluate only' : status?.agentConfigured ? 'Not authenticated' : 'Not configured'} /></div></div>
            <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Proposal function grant</span><StatusPill state={memberPillState(status?.delegationMemberState)} label={memberLabel(status?.delegationMemberState)} /></div></div>
            <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Proposal effective Guard runtime access</span><StatusPill state={effectivePillState(status?.delegationEffectiveState)} label={effectiveLabel(status?.delegationEffectiveState)} /></div></div>
            <div className="status-item"><UserRoundCog aria-hidden="true" /><div><span>Protected executor</span><StatusPill state={status?.executorAuthenticated ? 'ok' : 'off'} label={status?.executorAuthenticated ? 'Authenticated · execute + verify' : status?.executorConfigured ? 'Not authenticated' : 'Not configured'} /></div></div>
            <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Executor function grant</span><StatusPill state={memberPillState(status?.executorDelegationMemberState)} label={memberLabel(status?.executorDelegationMemberState)} /></div></div>
            <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Executor effective Guard runtime access</span><StatusPill state={effectivePillState(status?.executorDelegationEffectiveState)} label={effectiveLabel(status?.executorDelegationEffectiveState)} /></div></div>
            <div className="status-item"><Shield aria-hidden="true" /><div><span>Contract</span><StatusPill state={status?.contractResolved ? 'ok' : 'off'} label={status?.contractResolved ? `Resolved · v${status.contractVersion}` : 'Unavailable'} /></div></div>
            <div className="status-item"><Shield aria-hidden="true" /><div><span>Proposal evaluation</span><StatusPill state={status?.evaluationReady ? 'ok' : 'off'} label={status?.evaluationReady ? 'Ready' : 'Not ready'} /></div></div>
            <div className="status-item"><Shield aria-hidden="true" /><div><span>Protected remediation</span><StatusPill state={status?.protectedRemediationReady ? 'ok' : 'off'} label={status?.protectedRemediationReady ? 'Ready' : 'Not ready'} /></div></div>
          </div>
          <div className="status-meta">
            <div><span>Tenant id</span><code>{status?.tenantDid ?? 'Unavailable'}</code></div>
            <div><span>Proposal agent caller</span><code>{status?.agentDid ?? 'Unavailable'}</code></div>
            <div><span>Protected executor caller</span><code>{status?.executorDid ?? 'Unavailable'}</code></div>
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
      <EnterpriseIntegrationStatus status={status} loading={loading} />
    </>
  );
}
