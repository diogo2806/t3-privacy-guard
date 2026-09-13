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
    delegationState: 'ACTIVE',
    delegationEffectiveState: 'ACTIVE',
    delegatedFunctions: ['evaluate-action'],
    delegatedScopes: ['incident_id', 'credential_id', 'reason'],
    allowedHosts: [],
    delegationCheckedFunctions: ['evaluate-action'],
    delegationCheckedScopes: ['incident_id', 'credential_id', 'reason'],
    executorDelegationState: 'ACTIVE',
    executorDelegationEffectiveState: 'ACTIVE',
    executorDelegatedFunctions: ['execute-remediation', 'verify-remediation'],
    executorDelegatedScopes: ['incident_id', 'credential_id', 'reason'],
    executorAllowedHosts: ['security.example'],
    executorDelegationCheckedFunctions: ['execute-remediation', 'verify-remediation'],
    executorDelegationCheckedScopes: ['incident_id', 'credential_id', 'reason'],
    message: 'Observed status.',
  };
}

describe('SystemStatusBar', () => {
  it('shows member grants and effective access for proposal and executor independently', () => {
    render(<SystemStatusBar status={status('REGISTERED')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Proposal member grant')).toBeInTheDocument();
    expect(screen.getByText('Proposal effective T3N access')).toBeInTheDocument();
    expect(screen.getByText('Executor member grant')).toBeInTheDocument();
    expect(screen.getByText('Executor effective T3N access')).toBeInTheDocument();
    expect(screen.getByText('Operational')).toBeInTheDocument();
    expect(screen.getAllByText('Confirmed')).toHaveLength(2);
    expect(screen.getByText('did:t3n:protected-executor')).toBeInTheDocument();
  });

  it('does not report operational when proposal effective access is denied', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), evaluationReady: false, protectedRemediationReady: false, delegationEffectiveState: 'DENIED' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Unavailable / incomplete')).toBeInTheDocument();
    expect(screen.getByText('Denied')).toHaveClass('status-pill-off');
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('shows evaluation-only readiness when executor effective access is denied', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), protectedRemediationReady: false, executorDelegationEffectiveState: 'DENIED' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Evaluation ready · execution blocked')).toBeInTheDocument();
    expect(screen.getByText('Denied')).toHaveClass('status-pill-off');
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('does not report operational when effective access is unknown', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), evaluationReady: false, protectedRemediationReady: false, delegationEffectiveState: 'UNKNOWN' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Unavailable / incomplete')).toBeInTheDocument();
    expect(screen.getByText('Unknown')).toHaveClass('status-pill-pending');
  });

  it('does not report operational when executor is unavailable', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), executorAuthenticated: false, protectedRemediationReady: false, executorDelegationState: 'UNKNOWN', executorDelegationEffectiveState: 'UNKNOWN' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Evaluation ready · execution blocked')).toBeInTheDocument();
  });

  it('renders a scheduled proposal delegation as pending and never operational', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), evaluationReady: false, protectedRemediationReady: false, delegationState: 'SCHEDULED', delegationEffectiveState: 'DENIED', message: 'Proposal delegation is scheduled.' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Scheduled').length).toBeGreaterThan(0);
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
    expect(screen.getByText(/authorization window has not begun/i)).toBeInTheDocument();
  });

  it('renders a scheduled executor delegation as pending and never operational', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), protectedRemediationReady: false, executorDelegationState: 'SCHEDULED', executorDelegationEffectiveState: 'DENIED', message: 'Executor delegation is scheduled.' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Scheduled').length).toBeGreaterThan(0);
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
    expect(screen.getByText(/authorization window has not begun/i)).toBeInTheDocument();
  });

  it('renders DID mismatch as a non-success onboarding state', () => {
    render(<SystemStatusBar status={status('MISMATCH')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Card/DID mismatch')).toHaveClass('status-pill-off');
  });
});