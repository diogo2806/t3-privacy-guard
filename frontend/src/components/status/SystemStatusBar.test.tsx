import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { SystemStatus } from '../../services/privacyGuardApi';
import { SystemStatusBar } from './SystemStatusBar';

const READY_STATUS: SystemStatus = {
  runtimeReachable: true,
  tenantAuthenticated: true,
  network: 'selfhosted',
  tenantDid: 'tenant:acme',
  agentConfigured: true,
  agentAuthenticated: true,
  agentDid: 'agent:proposal',
  executorConfigured: true,
  executorAuthenticated: true,
  executorDid: 'agent:executor',
  contractResolved: true,
  contractId: 'privacy-guard',
  contractVersion: '1.0.0',
  evaluationReady: true,
  protectedRemediationReady: true,
  enterpriseIntegrationState: 'READY',
  enterpriseIntegrationDiagnosticCode: 'NONE',
  enterpriseIntegrationReady: true,
  firstPartyRemediationAdapterConfigured: true,
  enterpriseExecutionConfigured: true,
  enterpriseVerificationConfigured: true,
  enterpriseCredentialConfigured: true,
  enterpriseExecutionHost: 'security.company.example',
  enterpriseVerificationHost: 'verify.company.example',
  enterprisePolicyAllowsExecutionHost: true,
  enterprisePolicyAllowsVerificationHost: true,
  enterpriseExecutorDelegationAllowsExecutionHost: true,
  enterpriseExecutorDelegationAllowsVerificationHost: true,
  enterpriseSupportedExecutableActions: ['revoke-credential'],
  enterpriseSupportedVerifiedActions: ['revoke-credential'],
  enterpriseVerificationContracts: [{ action: 'revoke-credential', expectedState: 'REVOKED' }],
  enterpriseEvaluationOnlyActions: ['create-incident', 'isolate-account', 'notify-security'],
  enterpriseIntegrationCheckedAt: '2026-10-28T11:00:00Z',
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
  executorAllowedHosts: ['security.company.example', 'verify.company.example'],
  executorDelegationCheckedFunctions: ['execute-remediation', 'verify-remediation'],
  executorDelegationCheckedScopes: ['incident_id', 'credential_id', 'reason'],
  message: 'Observed status.',
};

describe('SystemStatusBar', () => {
  it('shows function grants, effective access and independent Guard runtime readiness', () => {
    render(<SystemStatusBar status={READY_STATUS} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByRole('region', { name: 'Live Guard runtime operational status' })).toBeInTheDocument();
    expect(screen.getByText('Technical Guard runtime authorization')).toBeInTheDocument();
    expect(screen.getByText('Proposal function grant')).toBeInTheDocument();
    expect(screen.getByText('Proposal effective Guard runtime access')).toBeInTheDocument();
    expect(screen.getByText('Executor function grant')).toBeInTheDocument();
    expect(screen.getByText('Executor effective Guard runtime access')).toBeInTheDocument();
    expect(screen.getByText('Proposal evaluation')).toBeInTheDocument();
    expect(screen.getByText('Protected remediation')).toBeInTheDocument();
    expect(screen.getByText('Guard runtime controls ready')).toBeInTheDocument();
    expect(screen.getByText(/Guard runtime confirmed the exact function grants/)).toBeInTheDocument();
    expect(screen.getByText('Authenticated · selfhosted')).toBeInTheDocument();
    expect(screen.getAllByText('Confirmed')).toHaveLength(2);
    expect(screen.getByText('agent:executor')).toBeInTheDocument();
    expect(screen.getAllByText('evaluate-action').length).toBeGreaterThanOrEqual(2);
    expect(screen.getAllByText('execute-remediation, verify-remediation').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText('Enterprise integration')).toBeInTheDocument();
    expect(screen.getByText('Operational protected workflow')).toBeInTheDocument();
  });

  it('does not describe public agent onboarding or provider-specific identities', () => {
    render(<SystemStatusBar status={READY_STATUS} loading={false} onRefresh={vi.fn()} />);
    expect(document.body.textContent).not.toMatch(/Agent Card|A2A|onboarding|Member grant|DID/);
  });

  it('keeps evaluation ready while executor denial blocks protected remediation', () => {
    render(<SystemStatusBar status={{ ...READY_STATUS, protectedRemediationReady: false, executorDelegationEffectiveState: 'DENIED' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Evaluation ready · execution blocked')).toHaveClass('status-pill-pending');
    expect(screen.getByText('Denied')).toHaveClass('status-pill-off');
    expect(screen.queryByText('Guard runtime controls ready')).not.toBeInTheDocument();
  });

  it('fails closed when Proposal effective access is denied', () => {
    render(<SystemStatusBar status={{ ...READY_STATUS, evaluationReady: false, protectedRemediationReady: false, delegationEffectiveState: 'DENIED' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Denied').length).toBeGreaterThan(0);
    expect(screen.queryByText('Guard runtime controls ready')).not.toBeInTheDocument();
  });

  it('fails closed with the runtime name when Proposal effective verdict is unknown', () => {
    render(<SystemStatusBar status={{ ...READY_STATUS, evaluationReady: false, protectedRemediationReady: false, delegationEffectiveState: 'UNKNOWN' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Unknown').length).toBeGreaterThan(0);
    expect(screen.getByText('Guard runtime controls incomplete')).toBeInTheDocument();
    expect(screen.getByText(/One or more Guard runtime controls are unavailable or denied/)).toBeInTheDocument();
    expect(screen.queryByText('Guard runtime controls ready')).not.toBeInTheDocument();
  });

  it('renders a scheduled function grant with no checked restrictions', () => {
    render(<SystemStatusBar status={{ ...READY_STATUS, evaluationReady: false, protectedRemediationReady: false, delegationMemberState: 'SCHEDULED', delegationEffectiveState: 'DENIED', delegationCheckedFunctions: [], delegationCheckedScopes: [], message: 'Proposal function grant exists, but its authorization window has not begun.' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getAllByText('Scheduled').length).toBeGreaterThan(0);
    expect(screen.getAllByText('Not checked').length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText('Guard runtime controls ready')).not.toBeInTheDocument();
  });
});
