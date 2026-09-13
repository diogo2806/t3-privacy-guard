import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { ActionProposal, PolicyDecision, RemediationExecution } from '../../services/privacyGuardApi';
import { RemediationPanel } from './RemediationPanel';

const action: ActionProposal = {
  id: 'action-1', incidentId: 'incident-1', requestId: 'request-1', action: 'revoke-credential',
  resource: 'credential:test', purpose: 'incident-remediation', host: 'postman-echo.com',
  fields: ['incident_id', 'credential_id', 'reason'], privateRefs: [], status: 'REMEDIATION_AUTHORIZED', createdAt: '2026-09-12T18:00:00Z',
};

const decision: PolicyDecision = {
  id: 'decision-1', actionProposalId: action.id, decision: 'ALLOW', reasonCode: 'POLICY_ALLOW', reason: 'Allowed',
  allowedFields: action.fields, redactedFields: [], allowedPrivateRefs: [], redactedPrivateRefs: [], evaluatedAt: '2026-09-12T18:00:01Z',
};

function execution(state: RemediationExecution['state'], overrides: Partial<RemediationExecution> = {}): RemediationExecution {
  return {
    incidentId: action.incidentId,
    actionId: action.id,
    requestId: action.requestId,
    state,
    httpCode: 202,
    operationId: 'op-1',
    verificationAttempts: 1,
    startedAt: '2026-09-12T18:00:02Z',
    ...overrides,
  };
}

function renderPanel(current: RemediationExecution | null, onVerify = vi.fn(), currentAction: ActionProposal = action) {
  render(
    <RemediationPanel
      action={currentAction}
      decision={{ ...decision, actionProposalId: currentAction.id }}
      execution={current}
      busy={false}
      onAuthorize={vi.fn()}
      onExecute={vi.fn()}
      onVerify={onVerify}
    />,
  );
  return onVerify;
}

describe('RemediationPanel', () => {
  it('does not call accepted execution completed while verification is pending', () => {
    renderPanel(execution('PENDING_VERIFICATION'));
    expect(screen.getByText('PENDING')).toBeInTheDocument();
    expect(screen.getByText('IN PROGRESS')).toBeInTheDocument();
    expect(screen.queryByText('COMPLETED')).not.toBeInTheDocument();
  });

  it('offers read-back without offering a second execution for an unverified result', async () => {
    const user = userEvent.setup();
    const onVerify = renderPanel(execution('UNVERIFIED', { failureCode: 'VERIFICATION_UNAVAILABLE' }));
    expect(screen.getAllByText('UNVERIFIED')).toHaveLength(2);
    expect(screen.queryByRole('button', { name: 'Execute protected credential revocation' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Verify external state' }));
    expect(onVerify).toHaveBeenCalledTimes(1);
  });

  it('labels completed only after verified read-back', () => {
    renderPanel(execution('COMPLETED', { completedAt: '2026-09-12T18:00:03Z' }));
    expect(screen.getByText('VERIFIED')).toBeInTheDocument();
    expect(screen.getByText('COMPLETED')).toBeInTheDocument();
    expect(screen.getByText(/Independent read-back verified the expected external state/i)).toBeInTheDocument();
  });

  it('does not offer authorization or execution for actions without a verified completion contract', () => {
    const unsupported: ActionProposal = {
      ...action,
      id: 'action-isolate',
      action: 'isolate-account',
      resource: 'account:demo',
      fields: ['incident_id', 'account_id', 'reason'],
      status: 'EVALUATED',
    };
    renderPanel(null, vi.fn(), unsupported);

    expect(screen.getByText(/can be evaluated by the T3N policy/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Authorize/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Execute protected/i })).not.toBeInTheDocument();
  });
});
