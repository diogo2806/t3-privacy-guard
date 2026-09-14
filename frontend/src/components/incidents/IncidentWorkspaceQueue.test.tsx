import '@testing-library/jest-dom/vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { describe, expect, it, vi } from 'vitest';
import type { IncidentWorkspace } from '../../services/privacyGuardApi';
import { IncidentWorkspaceQueue } from './IncidentWorkspaceQueue';

const workspace: IncidentWorkspace = {
  generatedAt: '2026-09-14T13:00:00Z',
  attentionCount: 2,
  incidents: [
    {
      id: 'inc-critical',
      title: 'Credential compromise',
      severity: 'CRITICAL',
      incidentStatus: 'OPEN',
      createdAt: '2026-09-14T12:58:00Z',
      latestActionId: 'action-1',
      latestAction: 'revoke-credential',
      latestActionStatus: 'EVALUATED',
      policyDecision: 'ALLOW',
      remediationState: null,
      stage: 'HUMAN_APPROVAL_REQUIRED',
      nextRequiredAction: 'Authorize remediation',
      requiresAttention: true,
    },
    {
      id: 'inc-complete',
      title: 'Verified notification',
      severity: 'HIGH',
      incidentStatus: 'REMEDIATED',
      createdAt: '2026-09-14T12:30:00Z',
      latestActionId: 'action-2',
      latestAction: 'notify-security',
      latestActionStatus: 'REMEDIATED',
      policyDecision: 'ALLOW',
      remediationState: 'COMPLETED',
      stage: 'VERIFIED_COMPLETE',
      nextRequiredAction: 'No action required',
      requiresAttention: false,
    },
  ],
};

function renderQueue(overrides: Partial<ComponentProps<typeof IncidentWorkspaceQueue>> = {}) {
  const props: ComponentProps<typeof IncidentWorkspaceQueue> = {
    workspace,
    selectedIncidentId: 'inc-critical',
    loading: false,
    error: null,
    detailLoading: false,
    detailError: null,
    onSelect: vi.fn(),
    onRetry: vi.fn(),
    onRetrySelected: vi.fn(),
    ...overrides,
  };
  render(<IncidentWorkspaceQueue {...props} />);
  return props;
}

describe('IncidentWorkspaceQueue', () => {
  it('shows all active incidents and keeps terminal truth distinct from attention', () => {
    renderQueue();

    expect(screen.getByText('2 need attention')).toBeInTheDocument();
    expect(screen.getByText('Credential compromise')).toBeInTheDocument();
    expect(screen.getByText('Needs human approval')).toBeInTheDocument();
    expect(screen.getByText('Verified notification')).toBeInTheDocument();
    expect(screen.getByText('Verified complete')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Open Credential compromise/i })).toHaveAttribute('aria-current', 'true');
  });

  it('selects a case without embedding mutation controls in the queue', () => {
    const props = renderQueue();

    fireEvent.click(screen.getByRole('button', { name: /Open Verified notification/i }));
    expect(props.onSelect).toHaveBeenCalledWith(workspace.incidents[1]);
    expect(screen.queryByRole('button', { name: /authorize/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^execute/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /^verify/i })).not.toBeInTheDocument();
  });

  it('shows an actionable empty state instead of pretending the workspace failed', () => {
    renderQueue({ workspace: { ...workspace, attentionCount: 0, incidents: [] } });

    expect(screen.getByText('No active incidents.')).toBeInTheDocument();
    expect(screen.getByText(/Run a scenario or wait for a new incident/i)).toBeInTheDocument();
  });

  it('keeps list failure and selected-detail failure recoverable', () => {
    const listRetry = vi.fn();
    const { unmount } = render(<IncidentWorkspaceQueue workspace={null} selectedIncidentId={null} loading={false} error="Service unavailable" detailLoading={false} detailError={null} onSelect={vi.fn()} onRetry={listRetry} onRetrySelected={vi.fn()} />);
    fireEvent.click(screen.getByRole('button', { name: /^Retry$/i }));
    expect(listRetry).toHaveBeenCalledOnce();
    unmount();

    const detailRetry = vi.fn();
    renderQueue({ detailError: 'Incident is temporarily unavailable', onRetrySelected: detailRetry });
    fireEvent.click(screen.getByRole('button', { name: /Retry selected incident/i }));
    expect(detailRetry).toHaveBeenCalledOnce();
  });
});
