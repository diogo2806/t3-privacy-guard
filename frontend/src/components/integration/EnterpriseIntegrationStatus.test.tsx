import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { EnterpriseIntegrationState, SystemStatus } from '../../services/privacyGuardApi';
import { EnterpriseIntegrationStatus } from './EnterpriseIntegrationStatus';

function status(state: EnterpriseIntegrationState, adapterConfigured = true): SystemStatus {
  const ready = state === 'READY';
  return {
    protectedRemediationReady: true,
    enterpriseIntegrationState: state,
    enterpriseIntegrationReady: ready,
    firstPartyRemediationAdapterConfigured: adapterConfigured,
    enterpriseExecutionConfigured: state !== 'UNKNOWN',
    enterpriseVerificationConfigured: state !== 'INCOMPLETE' && state !== 'UNKNOWN',
    enterpriseCredentialConfigured: state !== 'UNKNOWN',
    enterpriseExecutionHost: state === 'UNKNOWN' ? null : 'security.company.example',
    enterpriseVerificationHost: state === 'INCOMPLETE' || state === 'UNKNOWN' ? null : 'verify.company.example',
    enterprisePolicyAllowsExecutionHost: ready,
    enterprisePolicyAllowsVerificationHost: ready,
    enterpriseExecutorDelegationAllowsExecutionHost: ready,
    enterpriseExecutorDelegationAllowsVerificationHost: ready,
    enterpriseSupportedExecutableActions: ['revoke-credential'],
    enterpriseSupportedVerifiedActions: ['revoke-credential'],
    enterpriseVerificationContracts: [{ action: 'revoke-credential', expectedState: 'REVOKED' }],
    enterpriseEvaluationOnlyActions: ['create-incident', 'isolate-account', 'notify-security'],
    enterpriseIntegrationCheckedAt: '2026-09-13T21:00:00Z',
  } as SystemStatus;
}

describe('EnterpriseIntegrationStatus', () => {
  it('shows READY only for coherent configuration, T3N protected readiness and the first-party adapter', () => {
    render(<EnterpriseIntegrationStatus status={status('READY')} loading={false} />);
    expect(screen.getAllByText('READY').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByRole('heading', { name: 'Protected execution integration' })).toBeInTheDocument();
    expect(screen.getByText('First-party remediation adapter').parentElement).toHaveTextContent('Configured');
    expect(screen.getByText('security.company.example')).toBeInTheDocument();
    expect(screen.getByText('verify.company.example')).toBeInTheDocument();
    expect(screen.getByText('revoke-credential → REVOKED')).toBeInTheDocument();
    expect(screen.getByText('create-incident, isolate-account, notify-security')).toBeInTheDocument();
    expect(screen.getByText(/does not claim endpoint health/i)).toBeInTheDocument();
    expect(screen.getByText(/controlled by Privacy Guard/i)).toBeInTheDocument();
  });

  it('keeps the workflow blocked when T3N is ready but the first-party adapter is not configured', () => {
    render(<EnterpriseIntegrationStatus status={status('READY', false)} loading={false} />);
    expect(screen.getByText('First-party remediation adapter').parentElement).toHaveTextContent('Not configured');
    expect(screen.getByText('Operational protected workflow').parentElement).toHaveTextContent('NOT READY');
  });

  it('shows INCOMPLETE without pretending that a missing read-back endpoint is healthy', () => {
    render(<EnterpriseIntegrationStatus status={status('INCOMPLETE')} loading={false} />);
    expect(screen.getByText('INCOMPLETE')).toHaveClass('status-pill-pending');
    expect(screen.getByText('Independent verification configured').parentElement).toHaveTextContent('No');
    expect(screen.getByText('Operational protected workflow').parentElement).toHaveTextContent('NOT READY');
  });

  it('shows MISMATCH as a non-success state independent from color', () => {
    render(<EnterpriseIntegrationStatus status={status('MISMATCH')} loading={false} />);
    expect(screen.getByText('MISMATCH')).toHaveClass('status-pill-off');
    expect(screen.getByText('Policy allows execution host').parentElement).toHaveTextContent('No');
    expect(screen.getByText('Operational protected workflow').parentElement).toHaveTextContent('NOT READY');
  });

  it('shows UNKNOWN fail-closed when protected configuration cannot be evaluated', () => {
    render(<EnterpriseIntegrationStatus status={status('UNKNOWN')} loading={false} />);
    expect(screen.getByText('UNKNOWN')).toHaveClass('status-pill-off');
    expect(screen.getByText('Execution host').parentElement).toHaveTextContent('Not configured');
    expect(screen.getByText('Operational protected workflow').parentElement).toHaveTextContent('NOT READY');
  });

  it('does not expose a full private URL or secret-shaped field', () => {
    const { container } = render(<EnterpriseIntegrationStatus status={status('READY')} loading={false} />);
    expect(container.textContent).not.toContain('https://');
    expect(container.textContent).not.toContain('/private/');
    expect(container.textContent).not.toContain('SECURITY_API_KEY');
  });
});
