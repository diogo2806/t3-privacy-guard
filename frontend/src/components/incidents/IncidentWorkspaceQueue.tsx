import { ChevronRight, ListChecks, RefreshCw } from 'lucide-react';
import type { IncidentWorkspace, IncidentWorkspaceItem, IncidentWorkspaceStage } from '../../services/privacyGuardApi';
import { Button } from '../ui/Button';
import { SectionHeader } from '../ui/SectionHeader';
import { StatusBadge, type StatusBadgeTone } from '../ui/StatusBadge';
import { Surface } from '../ui/Surface';

interface IncidentWorkspaceQueueProps {
  workspace: IncidentWorkspace | null;
  selectedIncidentId: string | null;
  loading: boolean;
  error: string | null;
  detailLoading: boolean;
  detailError: string | null;
  onSelect: (item: IncidentWorkspaceItem) => void;
  onRetry: () => void;
  onRetrySelected: () => void;
}

const STAGE_LABELS: Record<IncidentWorkspaceStage, string> = {
  NEEDS_ANALYSIS: 'Needs analysis',
  POLICY_EVALUATION_REQUIRED: 'Policy evaluation required',
  POLICY_BLOCKED: 'Blocked by policy',
  HUMAN_APPROVAL_REQUIRED: 'Needs human approval',
  POLICY_REVIEWED: 'Policy reviewed',
  AUTHORIZED_EXECUTION_PENDING: 'Execution pending',
  EXECUTION_IN_PROGRESS: 'Execution in progress',
  VERIFICATION_PENDING: 'Verification pending',
  VERIFIED_COMPLETE: 'Verified complete',
  UNVERIFIED_REVIEW_REQUIRED: 'Unverified / review required',
  FAILED_REVIEW_REQUIRED: 'Failed / review required',
  STATE_UNAVAILABLE: 'Review incident state',
};

function stageTone(stage: IncidentWorkspaceStage): StatusBadgeTone {
  if (stage === 'VERIFIED_COMPLETE') return 'low';
  if (stage === 'POLICY_BLOCKED' || stage === 'FAILED_REVIEW_REQUIRED') return 'critical';
  if (stage === 'HUMAN_APPROVAL_REQUIRED' || stage === 'VERIFICATION_PENDING' || stage === 'UNVERIFIED_REVIEW_REQUIRED') return 'high';
  return 'medium';
}

function formatCreatedAt(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString();
}

export function IncidentWorkspaceQueue({
  workspace,
  selectedIncidentId,
  loading,
  error,
  detailLoading,
  detailError,
  onSelect,
  onRetry,
  onRetrySelected,
}: IncidentWorkspaceQueueProps) {
  const incidents = workspace?.incidents ?? [];
  const attentionCount = workspace?.attentionCount ?? 0;

  return (
    <Surface className="incident-workspace" aria-labelledby="incident-workspace-title">
      <SectionHeader
        eyebrow="Operations"
        title="Incident workspace"
        titleId="incident-workspace-title"
        icon={<ListChecks aria-hidden="true" />}
        compact={false}
        trailing={<StatusBadge tone={attentionCount > 0 ? 'high' : 'low'}>{attentionCount} need attention</StatusBadge>}
      />
      <p className="card-copy">Select any active incident to resume its existing protected flow. Selecting a case never authorizes, executes, or verifies an action.</p>

      {loading && <p className="incident-workspace-status" role="status">Loading active incidents…</p>}

      {!loading && error && (
        <div className="incident-workspace-feedback" role="alert">
          <div>
            <strong>Incident workspace could not be loaded.</strong>
            <p>{error}</p>
          </div>
          <Button variant="secondary" onClick={onRetry}><RefreshCw aria-hidden="true" /> Retry</Button>
        </div>
      )}

      {!loading && !error && incidents.length === 0 && (
        <div className="incident-workspace-empty">
          <strong>No active incidents.</strong>
          <p>Run a scenario or wait for a new incident to start a protected decision flow.</p>
        </div>
      )}

      {!loading && !error && incidents.length > 0 && (
        <ul className="incident-workspace-list" aria-label="Active incidents">
          {incidents.map((item) => {
            const selected = selectedIncidentId === item.id;
            return (
              <li key={item.id}>
                <button
                  type="button"
                  className={`incident-workspace-row${selected ? ' incident-workspace-row-selected' : ''}`}
                  aria-current={selected ? 'true' : undefined}
                  aria-label={`Open ${item.title}. ${STAGE_LABELS[item.stage]}. Next action: ${item.nextRequiredAction}.`}
                  onClick={() => onSelect(item)}
                >
                  <StatusBadge tone={item.severity.toLowerCase() as StatusBadgeTone}>{item.severity}</StatusBadge>
                  <span className="incident-workspace-main">
                    <strong>{item.title}</strong>
                    <small>{item.nextRequiredAction}</small>
                  </span>
                  <span className="incident-workspace-state">
                    <StatusBadge tone={stageTone(item.stage)}>{STAGE_LABELS[item.stage]}</StatusBadge>
                    <time dateTime={item.createdAt}>{formatCreatedAt(item.createdAt)}</time>
                  </span>
                  <ChevronRight aria-hidden="true" />
                </button>
              </li>
            );
          })}
        </ul>
      )}

      {detailLoading && selectedIncidentId && <p className="incident-workspace-status" role="status">Loading selected incident…</p>}

      {!detailLoading && detailError && selectedIncidentId && (
        <div className="incident-workspace-feedback" role="alert">
          <div>
            <strong>Selected incident could not be opened.</strong>
            <p>{detailError}</p>
          </div>
          <Button variant="secondary" onClick={onRetrySelected}><RefreshCw aria-hidden="true" /> Retry selected incident</Button>
        </div>
      )}
    </Surface>
  );
}
