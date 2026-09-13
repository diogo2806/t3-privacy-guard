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
  agentDid: 'did:t3n:agent',
  agentRegistrationState: 'REGISTERED',
  agentCardServices: ['DID'],
  contractResolved: true,
  contractId: 'z:tenant:privacy-guard',
  contractVersion: '0.3.0',
  delegationState: 'ACTIVE',
  delegatedFunctions: ['evaluate-action'],
  allowedHosts: ['example.com'],
  message: 'Ready',
};

const ACTION: ActionProposal = {
  id: 'action-1',
  incidentId: 'incident-1',
  requestId: 'request-1',
  action: 'revoke-credential',
  resource: 'credential:1',
  purpose: 'incident-remediation',
  host: 'example.com',
  fields: ['incident_id', 'credential_id', 'reason'],
  privateRefs: [],
  status: 'EVALUATED',
  createdAt: '2026-09-12T00:00:00Z',
};

function decision(value: PolicyDecision['decision']): PolicyDecision {
  return {
    id: 'decision-1',
    actionProposalId: ACTION.id,
    decision: value,
    reasonCode: value,
    reason: value,
    allowedFields: [],
    redactedFields: [],
    allowedPrivateRefs: [],
    redactedPrivateRefs: [],
    evaluatedAt: '2026-09-12T00:00:01Z',
  };
}

function execution(state: RemediationExecution['state']): RemediationExecution {
  return {
    incidentId: ACTION.incidentId,
    actionId: ACTION.id,
    requestId: ACTION.requestId,
    state,
    verificationAttempts: state === 'COMPLETED' ? 1 : 0,
    startedAt: '2026-09-12T00:00:02Z',
    completedAt: state === 'COMPLETED' ? '2026-09-12T00:00:03Z' : null,
  };
}

function renderSummary(overrides: Partial<ComponentProps<typeof TrustFlowSummary>> = {}) {
  render(<TrustFlowSummary
    agentAnalysis={null}
    decision={null}
    selectedAction={null}
    remediationExecution={null}
    systemStatus={READY_STATUS}
    statusLoading={false}
    {...overrides}
  />);
}

describe('TrustFlowSummary', () => {
  it('starts with waiting states and never claims execution', () => {
    renderSummary();
    expect(screen.getAllByText('WAITING')).toHaveLength(2);
    expect(screen.getAllByText('NOT STARTED')).toHaveLength(2);
    expect(screen.getByText(/AI may propose an action, but it has no authority to execute it/i)).toBeInTheDocument();
  });

  it('shows DENY as blocked before protected egress', () => {
    renderSummary({ selectedAction: ACTION, decision: decision('DENY') });
    expect(screen.getByText('DENY')).toBeInTheDocument();
    expect(screen.getByText(/Policy blocked the proposal before protected egress. No execution is claimed./i)).toBeInTheDocument();
  });

  it('shows REDACT as minimization required without execution', () => {
    renderSummary({ selectedAction: ACTION, decision: decision('REDACT') });
    expect(screen.getByText('REDACT')).toBeInTheDocument();
    expect(screen.getByText(/requires data minimization/i)).toBeInTheDocument();
    expect(screen.getAllByText('NOT STARTED')).toHaveLength(2);
  });

  it('keeps ALLOW separate from human authorization and execution', () => {
    renderSummary({ selectedAction: ACTION, decision: decision('ALLOW') });
    expect(screen.getByText('ALLOW')).toBeInTheDocument();
    expect(screen.getByText('REQUIRED')).toBeInTheDocument();
    expect(screen.getByText(/blocked until a human authorizes it/i)).toBeInTheDocument();
  });

  it('shows human authorization without claiming execution', () => {
    renderSummary({ selectedAction: { ...ACTION, status: 'REMEDIATION_AUTHORIZED' }, decision: decision('ALLOW') });
    expect(screen.getByText('AUTHORIZED')).toBeInTheDocument();
    expect(screen.getByText(/No protected execution has been claimed yet/i)).toBeInTheDocument();
  });

  it('shows accepted execution as pending verification rather than completed', () => {
    renderSummary({
      selectedAction: { ...ACTION, status: 'REMEDIATION_AUTHORIZED' },
      decision: decision('ALLOW'),
      remediationExecution: execution('PENDING_VERIFICATION'),
    });
    expect(screen.getByText('ACCEPTED')).toBeInTheDocument();
    expect(screen.getByText('PENDING')).toBeInTheDocument();
    expect(screen.getByText(/Completion is pending independent verification/i)).toBeInTheDocument();
  });

  it('keeps UNVERIFIED explicit and never claims completion', () => {
    renderSummary({
      selectedAction: { ...ACTION, status: 'REMEDIATION_AUTHORIZED' },
      decision: decision('ALLOW'),
      remediationExecution: execution('UNVERIFIED'),
    });
    expect(screen.getAllByText('UNVERIFIED')).toHaveLength(2);
    expect(screen.getByText(/does not claim completion/i)).toBeInTheDocument();
  });

  it('keeps FAILED explicit and never claims verified completion', () => {
    renderSummary({
      selectedAction: { ...ACTION, status: 'REMEDIATION_AUTHORIZED' },
      decision: decision('ALLOW'),
      remediationExecution: execution('FAILED'),
    });
    expect(screen.getByText('FAILED')).toBeInTheDocument();
    expect(screen.getByText(/No verified completion is claimed/i)).toBeInTheDocument();
  });

  it('shows COMPLETED only when independent verification is completed', () => {
    renderSummary({
      selectedAction: { ...ACTION, status: 'REMEDIATED' },
      decision: decision('ALLOW'),
      remediationExecution: execution('COMPLETED'),
    });
    expect(screen.getByText('VERIFIED')).toBeInTheDocument();
    expect(screen.getByText(/remediation is COMPLETED/i)).toBeInTheDocument();
  });

  it('makes unavailable T3N controls explicit instead of green success', () => {
    const { container } = render(<TrustFlowSummary
      agentAnalysis={null}
      decision={null}
      selectedAction={null}
      remediationExecution={null}
      systemStatus={{ ...READY_STATUS, gatewayReachable: false }}
      statusLoading={false}
    />);
    expect(screen.getByText('T3N controls unavailable')).toBeInTheDocument();
    expect(screen.getByText(/cannot be proven until live status recovers/i)).toBeInTheDocument();
    expect(container.querySelector('.trust-readiness-unavailable')).toBeInTheDocument();
    expect(container.querySelector('.trust-readiness-ready')).not.toBeInTheDocument();
  });

  it('keeps a future delegation pending and never reports T3N controls ready', () => {
    const { container } = render(<TrustFlowSummary
      agentAnalysis={null}
      decision={null}
      selectedAction={null}
      remediationExecution={null}
      systemStatus={{ ...READY_STATUS, delegationState: 'SCHEDULED' }}
      statusLoading={false}
    />);
    expect(screen.getByText('Delegation scheduled')).toBeInTheDocument();
    expect(screen.getByText(/authorization window has not begun/i)).toBeInTheDocument();
    expect(container.querySelector('.trust-readiness-pending')).toBeInTheDocument();
    expect(container.querySelector('.trust-readiness-ready')).not.toBeInTheDocument();
  });
});
