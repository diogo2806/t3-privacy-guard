import { BadgeCheck, KeyRound, Link2, ShieldCheck } from 'lucide-react';
import type { EnterpriseIntegrationState, SystemStatus } from '../../services/privacyGuardApi';
import { StatusPill, type PillState } from '../status/StatusPill';

interface Props {
  status: SystemStatus | null;
  loading: boolean;
}

function integrationPillState(state?: EnterpriseIntegrationState): PillState {
  if (state === 'READY') return 'ok';
  if (state === 'INCOMPLETE') return 'pending';
  return 'off';
}

function booleanLabel(value: boolean | undefined): string {
  return value ? 'Yes' : 'No';
}

function booleanPill(value: boolean | undefined) {
  return <StatusPill state={value ? 'ok' : 'off'} label={booleanLabel(value)} />;
}

export function EnterpriseIntegrationStatus({ status, loading }: Props) {
  const integrationState = status?.enterpriseIntegrationState ?? 'UNKNOWN';
  const operational = Boolean(status?.protectedRemediationReady && status.enterpriseIntegrationReady);
  const verifiedContracts = status?.enterpriseVerificationContracts ?? [];
  const evaluationOnlyActions = status?.enterpriseEvaluationOnlyActions ?? [];

  return (
    <section className="status-panel status-panel-secondary" aria-label="Enterprise integration readiness">
      <div className="status-overview">
        <div>
          <p className="eyebrow">Enterprise integration</p>
          <h2>External execution readiness</h2>
          <p>
            {loading
              ? 'Checking whether protected execution, independent verification, active policy and Executor delegation are coherently configured.'
              : 'This is a read-only configuration and authorization check. It does not call the external service and does not claim endpoint health.'}
          </p>
        </div>
        <StatusPill state={loading ? 'pending' : integrationPillState(integrationState)} label={loading ? 'CHECKING' : integrationState} />
      </div>

      <div className="status-grid">
        <div className="status-item"><Link2 aria-hidden="true" /><div><span>Execution endpoint configured</span>{booleanPill(status?.enterpriseExecutionConfigured)}</div></div>
        <div className="status-item"><Link2 aria-hidden="true" /><div><span>Independent verification configured</span>{booleanPill(status?.enterpriseVerificationConfigured)}</div></div>
        <div className="status-item"><KeyRound aria-hidden="true" /><div><span>Execution credential configured</span>{booleanPill(status?.enterpriseCredentialConfigured)}</div></div>
        <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Policy allows execution host</span>{booleanPill(status?.enterprisePolicyAllowsExecutionHost)}</div></div>
        <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Policy allows verification host</span>{booleanPill(status?.enterprisePolicyAllowsVerificationHost)}</div></div>
        <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Executor delegation allows execution host</span>{booleanPill(status?.enterpriseExecutorDelegationAllowsExecutionHost)}</div></div>
        <div className="status-item"><ShieldCheck aria-hidden="true" /><div><span>Executor delegation allows verification host</span>{booleanPill(status?.enterpriseExecutorDelegationAllowsVerificationHost)}</div></div>
        <div className="status-item"><BadgeCheck aria-hidden="true" /><div><span>Operational protected workflow</span><StatusPill state={operational ? 'ok' : 'off'} label={operational ? 'READY' : 'NOT READY'} /></div></div>
      </div>

      <div className="status-meta">
        <div><span>Execution host</span><code>{status?.enterpriseExecutionHost ?? 'Not configured'}</code></div>
        <div><span>Verification host</span><code>{status?.enterpriseVerificationHost ?? 'Not configured'}</code></div>
        <div><span>Readiness check</span><code>{status?.enterpriseIntegrationCheckedAt ? new Date(status.enterpriseIntegrationCheckedAt).toLocaleString() : 'Not available'}</code></div>
      </div>

      <div className="status-meta">
        <div>
          <span>Executable + verified</span>
          <code>{verifiedContracts.length ? verifiedContracts.map(({ action, expectedState }) => `${action} → ${expectedState}`).join(', ') : 'None confirmed'}</code>
        </div>
        <div>
          <span>Evaluation only</span>
          <code>{evaluationOnlyActions.length ? evaluationOnlyActions.join(', ') : 'None'}</code>
        </div>
      </div>

      <div className="status-footer">
        <p>Only canonical hostnames are shown. Secrets, private paths, query strings and fragments remain inside the protected configuration boundary.</p>
      </div>
    </section>
  );
}
