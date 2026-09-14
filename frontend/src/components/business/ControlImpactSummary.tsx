import { Activity, BadgeCheck, Clock3, Scissors, ShieldCheck } from 'lucide-react';
import type { BusinessImpact, BusinessImpactWindow } from '../../services/privacyGuardApi';
import { Button } from '../ui/Button';
import { SectionHeader } from '../ui/SectionHeader';
import { Surface } from '../ui/Surface';
import { formatObservedDuration } from './BusinessOutcomeSummary';

interface Props {
  impact: BusinessImpact | null;
  loading: boolean;
  error: string | null;
  window: BusinessImpactWindow;
  onWindowChange?: (window: BusinessImpactWindow) => void;
  compact?: boolean;
}

const WINDOWS: Array<{ value: BusinessImpactWindow; label: string }> = [
  { value: 'retained', label: 'Retained' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
];

function observedRate(value?: number | null): string {
  return value === null || value === undefined ? 'NOT OBSERVED' : `${value.toFixed(1)}%`;
}

function coverageLabel(impact: BusinessImpact): string {
  const from = new Date(impact.from);
  const to = new Date(impact.to);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) return 'Observed retained data';
  return `${from.toLocaleString()} – ${to.toLocaleString()}`;
}

function loadingOrError(loading: boolean, error: string | null): string | null {
  if (loading) return 'Loading measured control impact…';
  if (error) return `Measured control impact is unavailable: ${error}`;
  return null;
}

export function ControlImpactSummary({ impact, loading, error, window, onWindowChange, compact = false }: Props) {
  const stateMessage = loadingOrError(loading, error);

  if (compact) {
    return (
      <section className="control-impact-compact" aria-labelledby="control-impact-compact-title" data-testid="control-impact-compact">
        <div className="control-impact-compact-heading">
          <div><p className="eyebrow">Measured control impact</p><h2 id="control-impact-compact-title">Observed runtime outcomes</h2></div>
          {impact && <span>{impact.window === 'RETAINED' ? 'RETAINED DATA' : impact.window}</span>}
        </div>
        {stateMessage ? (
          <p className="control-impact-state">{stateMessage}</p>
        ) : impact ? (
          <>
            <div className="control-impact-compact-metrics">
              <strong>{impact.deniedBeforeEgress} <span>blocked</span></strong>
              <strong>{impact.minimizedDecisions} <span>minimized</span></strong>
              <strong>{impact.verifiedCompleted} <span>verified</span></strong>
              <strong>{formatObservedDuration(impact.medianDecisionMs ?? null)} <span>median decision</span></strong>
            </div>
            <p className="control-impact-note">Measured from retained runtime state. Financial ROI is not inferred.</p>
          </>
        ) : (
          <p className="control-impact-state">Measured control impact has not been loaded.</p>
        )}
      </section>
    );
  }

  return (
    <Surface className="business-outcome-card control-impact-card" elevated aria-labelledby="control-impact-title">
      <SectionHeader
        eyebrow="Measured control impact"
        title="Observed value of the control"
        titleId="control-impact-title"
        icon={<Activity aria-hidden="true" />}
        trailing={onWindowChange ? (
          <div className="control-impact-window" role="group" aria-label="Control impact observation window">
            {WINDOWS.map((option) => (
              <Button
                key={option.value}
                variant={window === option.value ? 'secondary' : 'ghost'}
                className="control-impact-window-button"
                aria-pressed={window === option.value}
                onClick={() => onWindowChange(option.value)}
                disabled={loading}
              >
                {option.label}
              </Button>
            ))}
          </div>
        ) : undefined}
      />

      {stateMessage ? (
        <p className="control-impact-state" role={error ? 'alert' : 'status'}>{stateMessage}</p>
      ) : impact ? (
        <>
          <div className="control-impact-primary-grid">
            <div><ShieldCheck aria-hidden="true" /><span>Evaluated actions</span><strong>{impact.evaluatedActions}</strong></div>
            <div><ShieldCheck aria-hidden="true" /><span>Blocked before egress</span><strong>{impact.deniedBeforeEgress}</strong></div>
            <div><Scissors aria-hidden="true" /><span>Minimized decisions</span><strong>{impact.minimizedDecisions}</strong></div>
            <div><BadgeCheck aria-hidden="true" /><span>Verified outcomes</span><strong>{impact.verifiedCompleted}</strong></div>
          </div>

          <div className="control-impact-detail-grid">
            <dl>
              <div><dt>Observed block rate</dt><dd>{observedRate(impact.blockedRatePct)}{impact.blockedRatePct != null ? ` (${impact.deniedBeforeEgress} of ${impact.evaluatedActions} evaluated)` : ''}</dd></div>
              <div><dt>Verified completion</dt><dd>{observedRate(impact.verifiedCompletionRatePct)}{impact.verifiedCompletionRatePct != null ? ` (${impact.verifiedCompleted} of ${impact.finalizedExecutions} finalized)` : ''}</dd></div>
              <div><dt>Human-authorized remediations</dt><dd>{impact.humanAuthorizedRemediations}</dd></div>
              <div><dt>Unverified / failed outcomes</dt><dd>{impact.unverified} / {impact.failed}</dd></div>
            </dl>
            <dl>
              <div><dt>Median policy decision</dt><dd><Clock3 aria-hidden="true" />{formatObservedDuration(impact.medianDecisionMs ?? null)}</dd></div>
              <div><dt>Median verified outcome</dt><dd><Clock3 aria-hidden="true" />{formatObservedDuration(impact.medianVerifiedOutcomeMs ?? null)}</dd></div>
              <div><dt>Redacted normal field names</dt><dd>{impact.redactedNormalFieldNames}</dd></div>
              <div><dt>Redacted private references</dt><dd>{impact.redactedPrivateRefs}</dd></div>
            </dl>
          </div>

          <p className="control-impact-coverage"><strong>Observed coverage:</strong> {coverageLabel(impact)}{impact.retentionLimited ? ' · Limited by configured retention.' : ''}</p>
          <p className="control-impact-note">Counts and timings come from persisted runtime state. REDACT counts policy minimization of field names/private references, not bytes or people. Financial ROI, breach cost avoided, risk-reduction percentage, SLA compliance and monetary savings are NOT MEASURED.</p>
        </>
      ) : (
        <p className="control-impact-state">No measured control impact has been observed yet.</p>
      )}
    </Surface>
  );
}
