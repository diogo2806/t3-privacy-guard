import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SystemStatus } from '../../services/privacyGuardApi';
import { SystemStatusBar } from './SystemStatusBar';

const SELF_HOSTED_STATUS: SystemStatus = {
  gatewayReachable: true,
  tenantAuthenticated: true,
  network: 'selfhosted',
  tenantDid: 'tenant:acme',
  agentConfigured: true,
  agentAuthenticated: true,
  agentDid: 'agent:proposal',
  executorConfigured: true,
  executorAuthenticated: true,
  executorDid: 'agent:executor',
  agentRegistrationState: 'REGISTERED',
  agentCardUri: 'https://guard.example/agent-card.json',
  agentCardSha256: 'a'.repeat(64),
  agentCardVerifiedAt: '2026-10-28T11:00:00Z',
  agentCardServices: ['A2A', 'DID'],
  a2aConfigured: true,
  a2aPublicUrl: 'https://guard.example/a2a',
  a2aConfigurationCheckedAt: '2026-10-28T11:00:00Z',
  contractResolved: true,
  contractId: 'guard-runtime',
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

afterEach(() => {
  cleanup();
});

describe('SystemStatusBar on the self-hosted guard-runtime', () => {
  it('names Guard runtime instead of T3N for readiness and effective access', () => {
    render(<SystemStatusBar status={SELF_HOSTED_STATUS} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByRole('region', { name: 'Live Guard runtime operational status' })).toBeInTheDocument();
    expect(screen.getByText('Technical Guard runtime authorization')).toBeInTheDocument();
    expect(screen.getByText('Guard runtime controls ready')).toBeInTheDocument();
    expect(screen.getByText(/Guard runtime confirmed the exact least-privilege access/)).toBeInTheDocument();
    expect(screen.getByText('Proposal effective Guard runtime access')).toBeInTheDocument();
    expect(screen.getByText('Executor effective Guard runtime access')).toBeInTheDocument();
    expect(screen.getByText('Authenticated · selfhosted')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('T3N');
  });

  it('keeps the incomplete state fail-closed with the runtime name', () => {
    render(<SystemStatusBar status={{ ...SELF_HOSTED_STATUS, evaluationReady: false, protectedRemediationReady: false, delegationEffectiveState: 'UNKNOWN' }} loading={false} onRefresh={vi.fn()} />);
    expect(screen.getByText('Guard runtime controls incomplete')).toBeInTheDocument();
    expect(screen.getByText(/One or more Guard runtime controls are unavailable or denied/)).toBeInTheDocument();
    expect(screen.queryByText('Guard runtime controls ready')).not.toBeInTheDocument();
  });
});
