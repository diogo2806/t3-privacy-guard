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
    agentDid: 'did:t3n:agent',
    agentRegistrationState,
    agentCardUri: agentRegistrationState === 'REGISTERED' ? 'https://node.example/card' : null,
    agentCardSha256: agentRegistrationState === 'REGISTERED' ? 'a'.repeat(64) : null,
    agentCardVerifiedAt: '2026-09-12T20:00:00Z',
    agentCardServices: agentRegistrationState === 'REGISTERED' ? ['DID'] : [],
    contractResolved: true,
    contractId: 'z:tenant:privacy-guard',
    contractVersion: '0.3.0',
    memberDelegationState: 'ACTIVE',
    delegationState: 'ACTIVE',
    delegatedFunctions: ['evaluate-action'],
    delegatedScopes: ['incident_id'],
    allowedHosts: ['security.example'],
    delegationSatisfied: ['member_delegation'],
    delegationMissing: [],
    message: 'Observed status.',
  };
}

describe('SystemStatusBar', () => {
  it('shows registration, member grant and effective access independently', () => {
    render(<SystemStatusBar status={status('REGISTERED')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Agent onboarding')).toBeInTheDocument();
    expect(screen.getByText('Registered')).toBeInTheDocument();
    expect(screen.getByText('Member grant')).toBeInTheDocument();
    expect(screen.getByText('Effective access')).toBeInTheDocument();
    expect(screen.getByText('ACTIVE')).toBeInTheDocument();
    expect(screen.getByText('Authorized')).toHaveClass('status-pill-ok');
  });

  it('renders DID mismatch as a non-success onboarding state', () => {
    render(<SystemStatusBar status={status('MISMATCH')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Card/DID mismatch')).toHaveClass('status-pill-off');
  });

  it('renders future member delegation as scheduled and never operational', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), memberDelegationState: 'SCHEDULED', delegationState: 'INCOMPLETE', message: 'Delegation is scheduled.' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Scheduled')).toHaveClass('status-pill-pending');
    expect(screen.getByText(/authorization window has not begun/i)).toBeInTheDocument();
    expect(screen.getByText('Unavailable / incomplete')).toBeInTheDocument();
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('never treats an active member grant as operational when platform access is incomplete', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), delegationState: 'INCOMPLETE' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Not authorized')).toHaveClass('status-pill-off');
    expect(screen.getByText(/did not confirm effective delegated access/i)).toBeInTheDocument();
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('renders unavailable platform verification as pending, not success', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), delegationState: 'UNKNOWN' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Unavailable')).toHaveClass('status-pill-pending');
    expect(screen.getByText(/effective-access check is unavailable/i)).toBeInTheDocument();
  });
});
