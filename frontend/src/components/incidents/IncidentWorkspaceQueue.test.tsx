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
      source: 'Approved integration: Security automation',
      originType: 'EXTERNAL',
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
      source: 'Synthetic scenario',
      originType: 'APPLICATION',
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
  it('shows all active incidents with source provenance and received time', () => {
    renderQueue();

    expect(screen.getByText('2 incidents need attention')).toBeInTheDocument();
    expect(screen.getByText('Credential compromise')).toBeInTheDocument();
    expect(screen.getByText('External · Source: Approved integration: Security automation')).toBeInTheDocument();
    expect(screen.getByText('Needs human approval')).toBeInTheDocument();
    expect(screen.getByText('Verified notification')).toBeInTheDocument();
    expect(screen.getByText('Demo / app · Source: Synthetic scenario')).toBeInTheDocument();
    expect(screen.getByText('Verified complete')).toBeInTheDocument();
    expect(screen.getAllByText(/Received /i)).toHaveLength(2);
    expect(screen.getByRole('button', { name: /Open Credential compromise/i })).toHaveAttribute('aria-current', 'true');
  });

  it('filters external and demo application incidents without changing backend state', () => {
    renderQueue();

    fireEvent.click(screen.getByRole('button', { name: 'External' }));
    expect(screen.getByText('Credential compromise')).toBeInTheDocument();
    expect(screen.queryByText('Verified notification')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Demo' }));
    expect(screen.queryByText('Credential compromise')).not.toBeInTheDocument();
    expect(screen.getByText('Verified notification')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'All' }));
    expect(screen.getByText('Credential compromise')).toBeInTheDocument();
    expect(screen.getByText('Verified notification')).toBeInTheDocument();
  });

  it('uses singular attention copy when exactly one incident requires action', () => {
    renderQueue({ workspace: { ...workspace, attentionCount: 1 } });
    expect(screen.getByText('1 incident needs attention')).toBeInTheDocument();
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

  it('shows a filtered empty state without reporting a load failure', () => {
    renderQueue({ workspace: { ...workspace, incidents: [workspace.incidents[0]] } });
    fireEvent.click(screen.getByRole('button', { name: 'Demo' }));

    expect(screen.getByText('No incidents match this source filter.')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
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
