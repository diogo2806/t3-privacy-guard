import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { ActionProposal, PolicyDecision, RemediationExecution } from '../../services/privacyGuardApi';
import { RemediationPanel } from './RemediationPanel';

const executorDid = 'did:t3n:protected-executor-test';
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
      executorDid={executorDid}
      busy={false}
      onAuthorize={vi.fn()}
      onExecute={vi.fn()}
      onVerify={onVerify}
    />,
  );
  return onVerify;
}

describe('RemediationPanel', () => {
  it('shows the approved destination, protected Executor DID and one-time proof requirement before execution', () => {
    renderPanel(null);
    expect(screen.getByText('Approved destination')).toBeInTheDocument();
    expect(screen.getByText('postman-echo.com')).toBeInTheDocument();
    expect(screen.getByText('Protected Executor DID')).toBeInTheDocument();
    expect(screen.getByText(executorDid)).toBeInTheDocument();
    expect(screen.getByText('ISSUED ON EXECUTE')).toBeInTheDocument();
    expect(screen.getByText(/same one-time Ed25519 human authorization proof/i)).toBeInTheDocument();
  });

  it('blocks authorization and execution when a supported action has no approved destination', () => {
    renderPanel(null, vi.fn(), { ...action, host: null, status: 'EVALUATED' });
    expect(screen.getByText('MISSING — BLOCKED')).toBeInTheDocument();
    expect(screen.getByRole('alert')).toHaveTextContent(/no approved destination/i);
    expect(screen.queryByRole('button', { name: /Authorize credential revocation/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Execute protected credential revocation/i })).not.toBeInTheDocument();
  });

  it('explains destination substitution as a new evaluation and authorization, not a generic outage', () => {
    renderPanel(execution('FAILED', { failureCode: 'EXECUTION_DESTINATION_CHANGED', operationId: null, httpCode: null }));
    expect(screen.getByRole('alert')).toHaveTextContent(/authorization proof was valid/i);
    expect(screen.getByRole('alert')).toHaveTextContent(/Create a new action/i);
    expect(screen.getByRole('alert')).toHaveTextContent(/authorize it before executing again/i);
  });

  it('shows both authorization boundaries only after protected execution confirms them', () => {
    renderPanel(execution('PENDING_VERIFICATION'));
    const status = screen.getByRole('region', { name: 'Remediation execution and verification status' });
    expect(status).toHaveTextContent('One-time authorization proofCONSUMED');
    expect(status).toHaveTextContent('Gateway proof checkVERIFIED');
    expect(status).toHaveTextContent('T3N contract proof checkT3N PROOF VERIFIED');
    expect(status).toHaveTextContent('External-state verificationPENDING');
    expect(status).toHaveTextContent('Final stateIN PROGRESS');
    expect(status).not.toHaveTextContent('Final stateCOMPLETED');
  });

  it('does not claim proof acceptance when a failed request has no protected response', () => {
    renderPanel(execution('FAILED', { httpCode: null, operationId: null, failureCode: 'AUTHORIZATION_PROOF_INVALID' }));
    const status = screen.getByRole('region', { name: 'Remediation execution and verification status' });
    expect(status).toHaveTextContent('One-time authorization proofNOT CONFIRMED');
    expect(status).toHaveTextContent('Gateway proof checkNOT CONFIRMED');
    expect(status).toHaveTextContent('T3N contract proof checkNOT CONFIRMED');
  });

  it('offers read-back without offering a second execution for an unverified result', async () => {
    const user = userEvent.setup();
    const onVerify = renderPanel(execution('UNVERIFIED', { failureCode: 'VERIFICATION_UNAVAILABLE' }));
    expect(screen.getAllByText('UNVERIFIED')).toHaveLength(2);
    expect(screen.queryByRole('button', { name: 'Execute protected credential revocation' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Verify external state' }));
    expect(onVerify).toHaveBeenCalledTimes(1);
  });

  it('labels completed only after proof checks and verified read-back', () => {
    renderPanel(execution('COMPLETED', { completedAt: '2026-09-12T18:00:03Z' }));
    const status = screen.getByRole('region', { name: 'Remediation execution and verification status' });
    expect(status).toHaveTextContent('Gateway proof checkVERIFIED');
    expect(status).toHaveTextContent('T3N contract proof checkT3N PROOF VERIFIED');
    expect(status).toHaveTextContent('External-state verificationVERIFIED');
    expect(status).toHaveTextContent('Final stateCOMPLETED');
    expect(screen.getByText(/Both authorization boundaries accepted the one-time proof/i)).toBeInTheDocument();
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
