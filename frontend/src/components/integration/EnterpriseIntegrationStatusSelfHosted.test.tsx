import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { EnterpriseIntegrationDiagnosticCode, SystemStatus } from '../../services/privacyGuardApi';
import { EnterpriseIntegrationStatus } from './EnterpriseIntegrationStatus';

function unknownStatus(network: string, diagnosticCode?: EnterpriseIntegrationDiagnosticCode): SystemStatus {
  const status: Partial<SystemStatus> = {
    network,
    protectedRemediationReady: false,
    enterpriseIntegrationState: 'UNKNOWN',
    enterpriseIntegrationDiagnosticCode: diagnosticCode,
    enterpriseIntegrationReady: false,
    firstPartyRemediationAdapterConfigured: true,
    enterpriseExecutionConfigured: null,
    enterpriseVerificationConfigured: null,
    enterpriseCredentialConfigured: null,
    enterpriseExecutionHost: null,
    enterpriseVerificationHost: null,
    enterprisePolicyAllowsExecutionHost: null,
    enterprisePolicyAllowsVerificationHost: null,
    enterpriseExecutorDelegationAllowsExecutionHost: null,
    enterpriseExecutorDelegationAllowsVerificationHost: null,
    enterpriseSupportedExecutableActions: [],
    enterpriseSupportedVerifiedActions: [],
    enterpriseVerificationContracts: [],
    enterpriseEvaluationOnlyActions: [],
    enterpriseIntegrationCheckedAt: '2026-10-28T12:00:00Z',
  };
  return status as SystemStatus;
}

afterEach(() => {
  cleanup();
});

describe('EnterpriseIntegrationStatus on the self-hosted guard-runtime', () => {
  it('explains an unreachable guard-runtime with its own allowlisted diagnostic', () => {
    render(<EnterpriseIntegrationStatus status={unknownStatus('selfhosted', 'TRUST_RUNTIME_UNAVAILABLE')} loading={false} />);
    expect(screen.getByText('TRUST_RUNTIME_UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getByText(/The self-hosted guard-runtime could not be reached, so readiness could not be confirmed\./)).toBeInTheDocument();
    expect(screen.getByText(/reported separately from Guard runtime authorization/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('T3N');
  });

  it('falls back to the guard-runtime diagnostic when an UNKNOWN self-hosted status omits the code', () => {
    render(<EnterpriseIntegrationStatus status={unknownStatus('selfhosted')} loading={false} />);
    expect(screen.getByText('TRUST_RUNTIME_UNAVAILABLE')).toBeInTheDocument();
    expect(screen.queryByText('T3N_CONTROL_PLANE_UNAVAILABLE')).not.toBeInTheDocument();
  });

  it('names Guard runtime in runtime-specific diagnostics', () => {
    render(<EnterpriseIntegrationStatus status={unknownStatus('selfhosted', 'POLICY_UNAVAILABLE')} loading={false} />);
    expect(screen.getByText(/The active protected policy could not be read from Guard runtime\./)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('T3N');
  });

  it('keeps the T3N control-plane fallback on T3N networks', () => {
    render(<EnterpriseIntegrationStatus status={unknownStatus('testnet')} loading={false} />);
    expect(screen.getByText('T3N_CONTROL_PLANE_UNAVAILABLE')).toBeInTheDocument();
    expect(screen.getByText(/T3N control-plane readiness could not be confirmed\./)).toBeInTheDocument();
  });
});
