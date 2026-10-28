import '@testing-library/jest-dom/vitest';
import type { ComponentProps } from 'react';
import { cleanup, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ActionProposal, PolicyDecision, SystemStatus } from '../../services/privacyGuardApi';
import { TrustFlowSummary } from './TrustFlowSummary';

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
  message: 'Ready',
};

const ACTION: ActionProposal = {
  id: 'action-1', incidentId: 'incident-1', requestId: 'request-1', action: 'revoke-credential', resource: 'credential:1',
  purpose: 'incident-remediation', host: 'example.com', fields: ['incident_id', 'credential_id', 'reason'], privateRefs: [],
  status: 'EVALUATED', createdAt: '2026-10-28T00:00:00Z',
};

function decision(value: PolicyDecision['decision']): PolicyDecision {
  return { id: 'decision-1', actionProposalId: ACTION.id, decision: value, reasonCode: value, reason: value, allowedFields: [], redactedFields: [], allowedPrivateRefs: [], redactedPrivateRefs: [], evaluatedAt: '2026-10-28T00:00:01Z' };
}

function renderSummary(overrides: Partial<ComponentProps<typeof TrustFlowSummary>> = {}) {
  render(<TrustFlowSummary agentAnalysis={null} decision={null} selectedAction={null} remediationExecution={null} systemStatus={SELF_HOSTED_STATUS} statusLoading={false} {...overrides} />);
}

afterEach(() => {
  cleanup();
});

describe('TrustFlowSummary on the self-hosted guard-runtime', () => {
  it('reports readiness against Guard runtime without the provider', () => {
    renderSummary({ selectedAction: ACTION });
    expect(screen.getByText('Guard runtime + external execution ready')).toBeInTheDocument();
    expect(screen.getByText('A proposal exists, but Guard runtime policy has not produced a decision yet.')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('T3N');
  });

  it('names Guard runtime when external integration is missing or executor access is denied', () => {
    renderSummary({ systemStatus: { ...SELF_HOSTED_STATUS, enterpriseIntegrationState: 'INCOMPLETE', enterpriseIntegrationReady: false } });
    expect(screen.getByText('Guard runtime authorization ready · external execution not configured')).toBeInTheDocument();
    expect(screen.getByText(/Guard runtime Proposal and Protected Executor authorization are ready/)).toBeInTheDocument();
    cleanup();

    renderSummary({ systemStatus: { ...SELF_HOSTED_STATUS, protectedRemediationReady: false, executorDelegationEffectiveState: 'DENIED' }, selectedAction: { ...ACTION, status: 'REMEDIATION_AUTHORIZED' }, decision: decision('ALLOW') });
    expect(screen.getByText(/Guard runtime denied Protected Executor access/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('T3N');
  });

  it('labels the pending-policy retry with the runtime name', async () => {
    const user = userEvent.setup();
    const onRetryEvaluation = vi.fn();
    renderSummary({ selectedAction: { ...ACTION, status: 'PENDING' }, onRetryEvaluation });
    expect(screen.getByText('The proposal is waiting for Guard runtime policy evaluation.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry Guard runtime evaluation' }));
    expect(onRetryEvaluation).toHaveBeenCalledTimes(1);
  });
});
