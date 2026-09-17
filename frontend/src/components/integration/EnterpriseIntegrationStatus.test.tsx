import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type {
  EnterpriseIntegrationDiagnosticCode,
  EnterpriseIntegrationState,
  SystemStatus,
} from '../../services/privacyGuardApi';
import { EnterpriseIntegrationStatus } from './EnterpriseIntegrationStatus';

function status(
  state: EnterpriseIntegrationState,
  adapterConfigured = true,
  diagnosticCode: EnterpriseIntegrationDiagnosticCode = state === 'UNKNOWN' ? 'T3N_CONTROL_PLANE_UNAVAILABLE' : 'NONE',
): SystemStatus {
  const ready = state === 'READY';
  const unknown = state === 'UNKNOWN';
  return {
    protectedRemediationReady: true,
    enterpriseIntegrationState: state,
    enterpriseIntegrationDiagnosticCode: diagnosticCode,
    enterpriseIntegrationReady: ready,
    firstPartyRemediationAdapterConfigured: adapterConfigured,
    enterpriseExecutionConfigured: unknown ? null : true,
    enterpriseVerificationConfigured: unknown ? null : state !== 'INCOMPLETE',
    enterpriseCredentialConfigured: unknown ? null : true,
    enterpriseExecutionHost: unknown ? null : 'security.company.example',
    enterpriseVerificationHost: state === 'INCOMPLETE' || unknown ? null : 'verify.company.example',
    enterprisePolicyAllowsExecutionHost: unknown ? null : ready,
    enterprisePolicyAllowsVerificationHost: unknown ? null : ready,
    enterpriseExecutorDelegationAllowsExecutionHost: unknown ? null : ready,
    enterpriseExecutorDelegationAllowsVerificationHost: unknown ? null : ready,
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
    expect(screen.queryByText(/Readiness diagnostic:/i)).not.toBeInTheDocument();
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
    expect(screen.getByText('Verification host').parentElement).toHaveTextContent('Not configured');
    expect(screen.getByText('Operational protected workflow').parentElement).toHaveTextContent('NOT READY');
  });

  it('shows MISMATCH as a non-success state independent from color', () => {
    render(<EnterpriseIntegrationStatus status={status('MISMATCH')} loading={false} />);
    expect(screen.getByText('MISMATCH')).toHaveClass('status-pill-off');
    expect(screen.getByText('Policy allows execution host').parentElement).toHaveTextContent('No');
    expect(screen.getByText('Operational protected workflow').parentElement).toHaveTextContent('NOT READY');
  });

  it('shows UNKNOWN for inconclusive facts while keeping observed adapter state and workflow fail-closed', () => {
    render(<EnterpriseIntegrationStatus status={status('UNKNOWN', true, 'POLICY_UNAVAILABLE')} loading={false} />);
    expect(screen.getByText('UNKNOWN')).toHaveClass('status-pill-off');
    expect(screen.getByText('Execution endpoint configured').parentElement).toHaveTextContent('Unknown');
    expect(screen.getByText('Independent verification configured').parentElement).toHaveTextContent('Unknown');
    expect(screen.getByText('Execution credential configured').parentElement).toHaveTextContent('Unknown');
    expect(screen.getByText('Policy allows execution host').parentElement).toHaveTextContent('Unknown');
    expect(screen.getByText('Executor delegation allows execution host').parentElement).toHaveTextContent('Unknown');
    expect(screen.getByText('Execution host').parentElement).toHaveTextContent('Unknown');
    expect(screen.getByText('Verification host').parentElement).toHaveTextContent('Unknown');
    expect(screen.getByText('First-party remediation adapter').parentElement).toHaveTextContent('Configured');
    expect(screen.getByText('Operational protected workflow').parentElement).toHaveTextContent('NOT READY');
    expect(screen.getByText('POLICY_UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getByText(/active protected policy could not be read from T3N/i)).toBeInTheDocument();
  });

  it('shows insufficient T3N credit as an actionable external provisioning condition without exposing balances or secrets', () => {
    const { container } = render(
      <EnterpriseIntegrationStatus status={status('UNKNOWN', true, 'INSUFFICIENT_CREDIT')} loading={false} />,
    );

    expect(screen.getByText('INSUFFICIENT_CREDIT')).toBeInTheDocument();
    expect(screen.getByText(/does not have enough credit/i)).toBeInTheDocument();
    expect(screen.getByText(/replenish T3N account credits and retry provisioning/i)).toBeInTheDocument();
    expect(screen.getByText('Operational protected workflow').parentElement).toHaveTextContent('NOT READY');
    expect(container.textContent).not.toContain('available=');
    expect(container.textContent).not.toContain('required=');
    expect(container.textContent).not.toContain('SECURITY_API_KEY');
  });

  it('falls back to a safe control-plane diagnostic for an older backend response', () => {
    const olderStatus = status('UNKNOWN');
    delete olderStatus.enterpriseIntegrationDiagnosticCode;

    render(<EnterpriseIntegrationStatus status={olderStatus} loading={false} />);

    expect(screen.getByText('T3N_CONTROL_PLANE_UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getByText(/control-plane readiness could not be confirmed/i)).toBeInTheDocument();
  });

  it('does not expose a full private URL or secret-shaped field', () => {
    const { container } = render(<EnterpriseIntegrationStatus status={status('UNKNOWN', true, 'PRIVATE_CONFIGURATION_UNAVAILABLE')} loading={false} />);
    expect(container.textContent).not.toContain('https://');
    expect(container.textContent).not.toContain('/private/');
    expect(container.textContent).not.toContain('SECURITY_API_KEY');
  });
});
