import '@testing-library/jest-dom/vitest';
import type { ComponentProps } from 'react';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ActionProposal, PolicyDecision, RemediationExecution, SystemStatus } from '../../services/privacyGuardApi';
import { TrustFlowSummary } from './TrustFlowSummary';

const READY_STATUS: SystemStatus = {
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
  agentRegistrationState: 'REGISTERED',
  agentCardServices: ['A2A', 'DID'],
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
  executorAllowedHosts: ['example.com'],
  executorDelegationCheckedFunctions: ['execute-remediation', 'verify-remediation'],
  executorDelegationCheckedScopes: ['incident_id', 'credential_id', 'reason'],
  message: 'Ready',
};

const ACTION: ActionProposal = {
  id: 'action-1', incidentId: 'incident-1', requestId: 'request-1', action: 'revoke-credential', resource: 'credential:1',
  purpose: 'incident-remediation', host: 'example.com', fields: ['incident_id', 'credential_id', 'reason'], privateRefs: [],
  status: 'EVALUATED', createdAt: '2026-09-12T00:00:00Z',
};

function decision(value: PolicyDecision['decision']): PolicyDecision {
  return { id: 'decision-1', actionProposalId: ACTION.id, decision: value, reasonCode: value, reason: value, allowedFields: [], redactedFields: [], allowedPrivateRefs: [], redactedPrivateRefs: [], evaluatedAt: '2026-09-12T00:00:01Z' };
}

function execution(state: RemediationExecution['state']): RemediationExecution {
  return { incidentId: ACTION.incidentId, actionId: ACTION.id, requestId: ACTION.requestId, state, verificationAttempts: state === 'COMPLETED' ? 1 : 0, startedAt: '2026-09-12T00:00:02Z', completedAt: state === 'COMPLETED' ? '2026-09-12T00:00:03Z' : null };
}

function renderSummary(overrides: Partial<ComponentProps<typeof TrustFlowSummary>> = {}) {
  render(<TrustFlowSummary agentAnalysis={null} decision={null} selectedAction={null} remediationExecution={null} systemStatus={READY_STATUS} statusLoading={false} {...overrides} />);
}

describe('TrustFlowSummary', () => {
  it('starts with waiting states and states the Proposal Agent cannot execute', () => {
    renderSummary();
    expect(screen.getAllByText('WAITING')).toHaveLength(2);
    expect(screen.getByText(/Proposal Agent has no authority to execute it/i)).toBeInTheDocument();
  });

  it('keeps ALLOW separate from human authorization and protected executor', () => {
    renderSummary({ selectedAction: ACTION, decision: decision('ALLOW') });
    expect(screen.getByText('ALLOW')).toBeInTheDocument();
    expect(screen.getByText('REQUIRED')).toBeInTheDocument();
    expect(screen.getByText(/Protected Executor remains blocked until a human authorizes it/i)).toBeInTheDocument();
  });

  it('shows accepted execution as pending verification rather than completed', () => {
    renderSummary({ selectedAction: { ...ACTION, status: 'REMEDIATION_AUTHORIZED' }, decision: decision('ALLOW'), remediationExecution: execution('PENDING_VERIFICATION') });
    expect(screen.getByText('ACCEPTED')).toBeInTheDocument();
    expect(screen.getByText('PENDING')).toBeInTheDocument();
    expect(screen.getByText(/Completion is pending independent verification/i)).toBeInTheDocument();
  });

  it('shows COMPLETED only after independent verification', () => {
    renderSummary({ selectedAction: { ...ACTION, status: 'REMEDIATED' }, decision: decision('ALLOW'), remediationExecution: execution('COMPLETED') });
    expect(screen.getByText('VERIFIED')).toBeInTheDocument();
    expect(screen.getByText(/remediation is COMPLETED/i)).toBeInTheDocument();
  });

  it('explicit Proposal denial fails closed', () => {
    const { container } = render(<TrustFlowSummary agentAnalysis={null} decision={null} selectedAction={null} remediationExecution={null} systemStatus={{ ...READY_STATUS, evaluationReady: false, protectedRemediationReady: false, delegationEffectiveState: 'DENIED' }} statusLoading={false} />);
    expect(screen.getByText('Effective access denied')).toBeInTheDocument();
    expect(screen.getByText(/T3N denied the exact effective access required for evaluation/i)).toBeInTheDocument();
    expect(container.querySelector('.trust-readiness-ready')).not.toBeInTheDocument();
  });

  it('unknown Proposal verdict fails closed', () => {
    const { container } = render(<TrustFlowSummary agentAnalysis={null} decision={null} selectedAction={null} remediationExecution={null} systemStatus={{ ...READY_STATUS, evaluationReady: false, protectedRemediationReady: false, delegationEffectiveState: 'UNKNOWN' }} statusLoading={false} />);
    expect(screen.getByText('Effective access unknown')).toBeInTheDocument();
    expect(screen.getByText(/could not be confirmed/i)).toBeInTheDocument();
    expect(container.querySelector('.trust-readiness-ready')).not.toBeInTheDocument();
  });

  it('keeps evaluation ready while Executor denial blocks execution', () => {
    const { container } = render(<TrustFlowSummary agentAnalysis={null} decision={null} selectedAction={null} remediationExecution={null} systemStatus={{ ...READY_STATUS, protectedRemediationReady: false, executorDelegationEffectiveState: 'DENIED' }} statusLoading={false} />);
    expect(screen.getByText('Evaluation ready · execution blocked')).toBeInTheDocument();
    expect(screen.getByText(/denied the Protected Executor effective access/i)).toBeInTheDocument();
    expect(container.querySelector('.trust-readiness-ready')).not.toBeInTheDocument();
  });

  it('keeps scheduled Proposal Member grant pending and not ready', () => {
    const { container } = render(<TrustFlowSummary agentAnalysis={null} decision={null} selectedAction={null} remediationExecution={null} systemStatus={{ ...READY_STATUS, evaluationReady: false, protectedRemediationReady: false, delegationMemberState: 'SCHEDULED', delegationEffectiveState: 'DENIED', delegationCheckedFunctions: [], delegationCheckedScopes: [] }} statusLoading={false} />);
    expect(screen.getByText('Member grant scheduled')).toBeInTheDocument();
    expect(screen.getByText(/no effective check is treated as active/i)).toBeInTheDocument();
    expect(container.querySelector('.trust-readiness-pending')).toBeInTheDocument();
  });
});
