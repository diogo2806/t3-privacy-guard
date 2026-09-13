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
    delegationMemberState: 'ACTIVE',
    delegationEffectiveState: 'ACTIVE',
    delegatedFunctions: ['evaluate-action'],
    delegatedScopes: ['incident_id'],
    allowedHosts: [],
    delegationSatisfied: ['member_delegation'],
    delegationMissing: [],
    executorDelegationMemberState: 'ACTIVE',
    executorDelegationEffectiveState: 'ACTIVE',
    executorDelegatedFunctions: ['execute-remediation', 'verify-remediation'],
    executorDelegatedScopes: ['incident_id', 'credential_id'],
    executorAllowedHosts: ['security.example'],
    executorDelegationSatisfied: ['member_delegation'],
    executorDelegationMissing: [],
    message: 'Observed status.',
  };
}

describe('SystemStatusBar', () => {
  it('shows Member grant, platform delegation and effective access independently', () => {
    render(<SystemStatusBar status={status('REGISTERED')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Proposal Member grant')).toBeInTheDocument();
    expect(screen.getByText('Proposal platform delegation')).toBeInTheDocument();
    expect(screen.getByText('Proposal effective access')).toBeInTheDocument();
    expect(screen.getByText('Executor Member grant')).toBeInTheDocument();
    expect(screen.getByText('Executor platform delegation')).toBeInTheDocument();
    expect(screen.getByText('Executor effective access')).toBeInTheDocument();
    expect(screen.getByText('Operational')).toBeInTheDocument();
    expect(screen.getAllByText('Authorized')).toHaveLength(2);
    expect(screen.getByText('did:t3n:protected-executor')).toBeInTheDocument();
  });

  it('does not report operational when executor is unavailable', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), executorAuthenticated: false, executorDelegationEffectiveState: 'UNKNOWN' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Unavailable / incomplete')).toBeInTheDocument();
  });

  it('does not report operational when Member grant is active but platform rejects access', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), delegationEffectiveState: 'INCOMPLETE', delegationMissing: ['required_authority'] }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Not authorized')).toHaveClass('status-pill-off');
    expect(screen.getByText('INCOMPLETE')).toHaveClass('status-pill-off');
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('does not report operational when effective delegation verdict is unavailable', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), delegationEffectiveState: 'UNKNOWN' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Unavailable')).toHaveClass('status-pill-off');
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('renders a scheduled proposal Member grant as pending and never checks platform access', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), delegationMemberState: 'SCHEDULED', delegationEffectiveState: 'INCOMPLETE', message: 'Proposal Member grant is scheduled.' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Scheduled').length).toBeGreaterThan(0);
    expect(screen.getByText('Not checked')).toHaveClass('status-pill-pending');
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
    expect(screen.getByText(/authorization window has not begun/i)).toBeInTheDocument();
  });

  it('renders a scheduled executor Member grant as pending and never operational', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), executorDelegationMemberState: 'SCHEDULED', executorDelegationEffectiveState: 'INCOMPLETE', message: 'Executor Member grant is scheduled.' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Scheduled').length).toBeGreaterThan(0);
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
    expect(screen.getByText(/authorization window has not begun/i)).toBeInTheDocument();
  });

  it('renders DID mismatch as a non-success onboarding state', () => {
    render(<SystemStatusBar status={status('MISMATCH')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Card/DID mismatch')).toHaveClass('status-pill-off');
  });
});
