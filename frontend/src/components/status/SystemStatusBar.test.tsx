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
    agentCardVerifiedAt: '2026-09-13T11:00:00Z',
    agentCardServices: agentRegistrationState === 'REGISTERED' ? ['A2A', 'DID'] : [],
    a2aConfigured: true,
    a2aPublicUrl: 'https://guard.example/a2a',
    a2aConfigurationCheckedAt: '2026-09-13T11:00:00Z',
    contractResolved: true,
    contractId: 'z:tenant:privacy-guard',
    contractVersion: '0.4.0',
    evaluationReady: true,
    protectedRemediationReady: true,
    delegationMemberState: 'ACTIVE',
    delegationEffectiveState: 'ACTIVE',
    delegatedFunctions: ['evaluate-action'],
    delegatedScopes: ['incident_id'],
    allowedHosts: [],
    delegationCheckedFunctions: ['evaluate-action'],
    delegationCheckedScopes: ['incident_id', 'credential_id', 'reason'],
    executorDelegationMemberState: 'ACTIVE',
    executorDelegationEffectiveState: 'ACTIVE',
    executorDelegatedFunctions: ['execute-remediation', 'verify-remediation'],
    executorDelegatedScopes: ['incident_id', 'credential_id'],
    executorAllowedHosts: ['security.example'],
    executorDelegationCheckedFunctions: ['execute-remediation', 'verify-remediation'],
    executorDelegationCheckedScopes: ['incident_id', 'credential_id', 'reason'],
    message: 'Observed status.',
  };
}

describe('SystemStatusBar', () => {
  it('shows Member grant, effective access and independent readiness', () => {
    render(<SystemStatusBar status={status('REGISTERED')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Proposal Member grant')).toBeInTheDocument();
    expect(screen.getByText('Proposal effective T3N access')).toBeInTheDocument();
    expect(screen.getByText('Executor Member grant')).toBeInTheDocument();
    expect(screen.getByText('Executor effective T3N access')).toBeInTheDocument();
    expect(screen.getByText('Proposal evaluation')).toBeInTheDocument();
    expect(screen.getByText('Protected remediation')).toBeInTheDocument();
    expect(screen.getByText('Operational')).toBeInTheDocument();
    expect(screen.getAllByText('Confirmed')).toHaveLength(2);
    expect(screen.getByText('did:t3n:protected-executor')).toBeInTheDocument();
    expect(screen.getAllByText('evaluate-action').length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText('execute-remediation, verify-remediation').length).toBeGreaterThanOrEqual(2);
  });

  it('shows A2A as published only when the resolved Agent Card contains the service', () => {
    render(<SystemStatusBar status={status('REGISTERED')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('A2A evaluation service')).toBeInTheDocument();
    expect(screen.getByText('Published')).toHaveClass('status-pill-ok');
    expect(screen.getByText('Yes · observed in resolved Agent Card')).toBeInTheDocument();
    expect(screen.getByText('https://guard.example/a2a')).toBeInTheDocument();
    expect(screen.getByText('Policy evaluation only')).toBeInTheDocument();
    expect(screen.getByText('Not exposed')).toBeInTheDocument();
    expect(screen.getByText('Not performed by this status check')).toBeInTheDocument();
  });

  it('does not promote local A2A configuration to a published or live-verified state', () => {
    const configuredOnly = { ...status('REGISTERED'), agentCardServices: ['DID'] };
    render(<SystemStatusBar status={configuredOnly} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Configured · not published')).toHaveClass('status-pill-pending');
    expect(screen.getByText('No')).toBeInTheDocument();
  });

  it('keeps evaluation ready while executor denial blocks protected remediation', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), protectedRemediationReady: false, executorDelegationEffectiveState: 'DENIED' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Evaluation ready · execution blocked')).toHaveClass('status-pill-pending');
    expect(screen.getByText('Denied')).toHaveClass('status-pill-off');
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('fails closed when Proposal effective access is denied', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), evaluationReady: false, protectedRemediationReady: false, delegationEffectiveState: 'DENIED' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Denied')).toHaveClass('status-pill-off');
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('fails closed when Proposal effective verdict is unknown', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), evaluationReady: false, protectedRemediationReady: false, delegationEffectiveState: 'UNKNOWN' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Unknown')).toHaveClass('status-pill-off');
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('renders scheduled Member grant with no checked restrictions', () => {
    render(<SystemStatusBar status={{ ...status('REGISTERED'), evaluationReady: false, protectedRemediationReady: false, delegationMemberState: 'SCHEDULED', delegationEffectiveState: 'DENIED', delegationCheckedFunctions: [], delegationCheckedScopes: [], message: 'Proposal Member grant exists, but its authorization window has not begun.' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Scheduled').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Not checked').length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText('Operational')).not.toBeInTheDocument();
  });

  it('renders DID mismatch as a non-success onboarding state without changing authorization', () => {
    render(<SystemStatusBar status={status('MISMATCH')} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Card/DID mismatch')).toHaveClass('status-pill-off');
    expect(screen.getByText('Operational')).toBeInTheDocument();
  });
});
