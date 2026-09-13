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
    delegationState: 'ACTIVE',
    delegatedFunctions: ['evaluate-action'],
    allowedHosts: [],
    executorDelegationState: 'ACTIVE',
    executorDelegatedFunctions: ['execute-remediation', 'verify-remediation'],
    executorAllowedHosts: ['security.example'],
    message: 'Observed status.',
  };
}

describe('SystemStatusBar', () => {
  it('shows proposal agent and protected executor independently', () => {
    render(<SystemStatusBar status={status('REGISTERED')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Proposal agent')).toBeInTheDocument();
    expect(screen.getByText('Protected executor')).toBeInTheDocument();
    expect(screen.getByText('Proposal delegation')).toBeInTheDocument();
    expect(screen.getByText('Executor delegation')).toBeInTheDocument();
    expect(screen.getByText('Operational')).toBeInTheDocument();
    expect(screen.getByText('did:t3n:protected-executor')).toBeInTheDocument();
  });

  it('does not report operational when executor is unavailable', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), executorAuthenticated: false, executorDelegationState: 'UNKNOWN' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Unavailable / incomplete')).toBeInTheDocument();
  });

  it('renders a scheduled proposal delegation as pending and never operational', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), delegationState: 'SCHEDULED', message: 'Proposal delegation is scheduled.' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Scheduled').length).toBeGreaterThan(0);
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
    expect(screen.getByText(/authorization window has not begun/i)).toBeInTheDocument();
  });

  it('renders a scheduled executor delegation as pending and never operational', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), executorDelegationState: 'SCHEDULED', message: 'Executor delegation is scheduled.' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Scheduled').length).toBeGreaterThan(0);
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
    expect(screen.getByText(/authorization window has not begun/i)).toBeInTheDocument();
  });

  it('renders DID mismatch as a non-success onboarding state', () => {
    render(<SystemStatusBar status={status('MISMATCH')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Card/DID mismatch')).toHaveClass('status-pill-off');
  });
});
