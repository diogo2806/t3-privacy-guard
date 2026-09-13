import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { SystemStatus } from '../../services/privacyGuardApi';
import { SystemStatusBar } from './SystemStatusBar';

function status(agentRegistrationState: SystemStatus['agentRegistrationState']): SystemStatus {
  return {
    gatewayReachable: true,
    tenantAuthenticated: true,
    network: 'testnet',
    tenantDid: 'did:t3n:tenant',
    agentConfigured: true,
    agentAuthenticated: true,
    agentDid: 'did:t3n:proposal-agent',
    executorConfigured: true,
    executorAuthenticated: true,
    executorDid: 'did:t3n:protected-executor',
    agentRegistrationState,
    agentCardUri: agentRegistrationState === 'REGISTERED' ? 'https://node.example/card' : null,
    agentCardSha256: agentRegistrationState === 'REGISTERED' ? 'a'.repeat(64) : null,
    agentCardVerifiedAt: '2026-09-12T20:00:00Z',
    agentCardServices: agentRegistrationState === 'REGISTERED' ? ['DID'] : [],
    contractResolved: true,
    contractId: 'z:tenant:privacy-guard',
    contractVersion: '0.4.0',
    evaluationReady: true,
    protectedRemediationReady: true,
    proposalMemberState: 'ACTIVE',
    proposalEffectiveState: 'ACTIVE',
    proposalDelegatedFunctions: ['evaluate-action'],
    proposalDelegatedScopes: ['incident_id', 'credential_id', 'reason'],
    proposalAllowedHosts: [],
    proposalCheckedFunctions: ['evaluate-action'],
    proposalCheckedScopes: ['incident_id', 'credential_id', 'reason'],
    executorMemberState: 'ACTIVE',
    executorEffectiveState: 'ACTIVE',
    executorDelegatedFunctions: ['execute-remediation', 'verify-remediation'],
    executorDelegatedScopes: ['incident_id', 'credential_id', 'reason'],
    executorAllowedHosts: ['security.example'],
    executorCheckedFunctions: ['execute-remediation', 'verify-remediation'],
    executorCheckedScopes: ['incident_id', 'credential_id', 'reason'],
    message: 'Observed status.',
  };
}

describe('SystemStatusBar', () => {
  it('separates Member grants from effective T3N access for both principals', () => {
    render(<SystemStatusBar status={status('REGISTERED')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Proposal member grant')).toBeInTheDocument();
    expect(screen.getByText('Proposal effective T3N access')).toBeInTheDocument();
    expect(screen.getByText('Executor member grant')).toBeInTheDocument();
    expect(screen.getByText('Executor effective T3N access')).toBeInTheDocument();
    expect(screen.getAllByText('Confirmed')).toHaveLength(2);
    expect(screen.getByText('Operational')).toBeInTheDocument();
    expect(screen.getByText('did:t3n:protected-executor')).toBeInTheDocument();
  });

  it('does not report operational when an active Proposal Member grant is effectively denied', () => {
    render(<SystemStatusBar status={{
      ...status('REGISTERED'),
      evaluationReady: false,
      protectedRemediationReady: false,
      proposalEffectiveState: 'DENIED',
      message: 'Proposal Member grant is active, but effective T3N access is denied.',
    }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Denied')).toHaveClass('status-pill-off');
    expect(screen.getByText('Unavailable / incomplete')).toBeInTheDocument();
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('does not report operational when Executor effective access is unknown', () => {
    render(<SystemStatusBar status={{
      ...status('REGISTERED'),
      protectedRemediationReady: false,
      executorEffectiveState: 'UNKNOWN',
      message: 'Protected Executor effective T3N access is unknown.',
    }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Unknown')).toHaveClass('status-pill-off');
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('renders a scheduled Proposal Member grant as pending and never operational', () => {
    render(<SystemStatusBar status={{
      ...status('REGISTERED'),
      evaluationReady: false,
      protectedRemediationReady: false,
      proposalMemberState: 'SCHEDULED',
      proposalEffectiveState: 'DENIED',
      proposalCheckedFunctions: [],
      proposalCheckedScopes: [],
      message: 'Proposal Member grant exists, but its authorization window has not begun. Effective T3N access is not confirmed.',
    }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Scheduled').length).toBeGreaterThan(0);
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
    expect(screen.getByText(/authorization window has not begun/i)).toBeInTheDocument();
  });

  it('renders DID mismatch as a non-success onboarding state without changing effective authorization', () => {
    render(<SystemStatusBar status={status('MISMATCH')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Card/DID mismatch')).toHaveClass('status-pill-off');
    expect(screen.getByText('Operational')).toBeInTheDocument();
  });
});
