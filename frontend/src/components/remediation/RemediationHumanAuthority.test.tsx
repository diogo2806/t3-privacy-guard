import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  privacyGuardApi,
  type ActionProposal,
  type OperatorSession,
  type PolicyDecision,
  type RemediationExecution,
} from '../../services/privacyGuardApi';
import { RemediationPanel } from './RemediationPanel';

const authorizedAction: ActionProposal = {
  id: 'action-1',
  incidentId: 'incident-1',
  requestId: 'request-1',
  action: 'revoke-credential',
  resource: 'credential:test',
  purpose: 'incident-remediation',
  host: 'security.example',
  fields: ['incident_id', 'credential_id', 'reason'],
  normalPayload: { incident_id: 'inc-1', credential_id: 'cred-1', reason: 'suspected compromise' },
  privateRefs: [],
  status: 'REMEDIATION_AUTHORIZED',
  createdAt: '2026-09-14T12:00:00Z',
  remediationAuthorizedBy: 'approver-01',
  remediationAuthorizedAt: '2026-09-14T12:01:00Z',
};

const decision: PolicyDecision = {
  id: 'decision-1',
  actionProposalId: authorizedAction.id,
  decision: 'ALLOW',
  reasonCode: 'POLICY_ALLOW',
  reason: 'Allowed',
  allowedFields: authorizedAction.fields,
  redactedFields: [],
  allowedPrivateRefs: [],
  redactedPrivateRefs: [],
  evaluatedAt: '2026-09-14T12:00:30Z',
};

function session(username: string, authorities: OperatorSession['authorities'], enterprise = true): OperatorSession {
  return { authenticated: true, username, authorities, enterpriseSeparationOfDuties: enterprise };
}

function renderPanel(action: ActionProposal, execution: RemediationExecution | null = null) {
  render(
    <RemediationPanel
      action={action}
      decision={{ ...decision, actionProposalId: action.id }}
      execution={execution}
      busy={false}
      onAuthorize={vi.fn()}
      onExecute={vi.fn()}
      onVerify={vi.fn()}
    />,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe('RemediationPanel human authority', () => {
  it('does not expose approval to an EXECUTOR-only session', () => {
    vi.spyOn(privacyGuardApi, 'currentSession').mockReturnValue(session('executor-01', ['EXECUTOR']));
    renderPanel({
      ...authorizedAction,
      status: 'EVALUATED',
      remediationAuthorizedBy: null,
      remediationAuthorizedAt: null,
    });

    expect(screen.getByText(/your human authority cannot approve remediation/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Authorize credential revocation/i })).not.toBeInTheDocument();
  });

  it('allows a different EXECUTOR principal to start an already authorized remediation', () => {
    vi.spyOn(privacyGuardApi, 'currentSession').mockReturnValue(session('executor-01', ['EXECUTOR']));
    renderPanel(authorizedAction);

    expect(screen.getByRole('button', { name: 'Execute protected credential revocation' })).toBeInTheDocument();
    expect(screen.getByText('NOT YET PROVEN')).toBeInTheDocument();
  });

  it('blocks the approving principal from executing even when it also has EXECUTOR authority', () => {
    vi.spyOn(privacyGuardApi, 'currentSession').mockReturnValue(session('approver-01', ['APPROVER', 'EXECUTOR']));
    renderPanel(authorizedAction);

    expect(screen.getByRole('alert')).toHaveTextContent(/same principal authorized the remediation/i);
    expect(screen.queryByRole('button', { name: 'Execute protected credential revocation' })).not.toBeInTheDocument();
  });

  it('shows confirmed separation only from persisted non-equal execution provenance', () => {
    vi.spyOn(privacyGuardApi, 'currentSession').mockReturnValue(session('auditor-01', ['AUDITOR']));
    renderPanel(authorizedAction, {
      incidentId: authorizedAction.incidentId,
      actionId: authorizedAction.id,
      requestId: authorizedAction.requestId,
      state: 'COMPLETED',
      httpCode: 202,
      operationId: 'op-1',
      verificationAttempts: 1,
      startedAt: '2026-09-14T12:02:00Z',
      completedAt: '2026-09-14T12:03:00Z',
      executionPrincipal: 'executor-01',
    });

    expect(screen.getByText('Execution principal')).toBeInTheDocument();
    expect(screen.getByText('executor-01')).toBeInTheDocument();
    expect(screen.getByText('Separation of duties')).toBeInTheDocument();
    expect(screen.getByText('CONFIRMED')).toBeInTheDocument();
  });
});
