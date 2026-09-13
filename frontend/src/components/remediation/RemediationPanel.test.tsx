import '@testing-library/jest-dom/vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { ActionProposal, PolicyDecision, RemediationExecution } from '../../services/privacyGuardApi';
import { RemediationPanel } from './RemediationPanel';

const action: ActionProposal = {
  id: 'action-1', incidentId: 'incident-1', requestId: 'request-1', action: 'revoke-credential',
  resource: 'credential:test', purpose: 'incident-remediation', host: 'postman-echo.com',
  fields: ['incident_id', 'credential_id', 'reason'],
  normalPayload: { incident_id: 'inc-demo-001', credential_id: 'cred-demo-001', reason: 'suspected compromise' },
  privateRefs: [], status: 'REMEDIATION_AUTHORIZED', createdAt: '2026-09-12T18:00:00Z',
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

function renderPanel(
  current: RemediationExecution | null,
  onVerify = vi.fn(),
  currentAction: ActionProposal = action,
  currentDecision: PolicyDecision = { ...decision, actionProposalId: currentAction.id },
) {
  render(
    <RemediationPanel
      action={currentAction}
      decision={currentDecision}
      execution={current}
      busy={false}
      onAuthorize={vi.fn()}
      onExecute={vi.fn()}
      onVerify={onVerify}
    />,
  );
  return onVerify;
}

function notificationAction(status: ActionProposal['status'] = 'REMEDIATION_AUTHORIZED'): ActionProposal {
  return {
    ...action,
    id: 'action-notify',
    requestId: 'request-notify',
    action: 'notify-security',
    resource: 'incident:synthetic',
    purpose: 'incident-notification',
    fields: ['incident_id', 'severity', 'summary'],
    normalPayload: { incident_id: 'inc-demo-001', severity: 'critical', summary: 'synthetic security incident' },
    privateRefs: ['verified_email'],
    status,
  };
}

function notificationDecision(currentAction = notificationAction()): PolicyDecision {
  return {
    ...decision,
    actionProposalId: currentAction.id,
    allowedFields: currentAction.fields,
    allowedPrivateRefs: ['verified_email'],
  };
}

describe('RemediationPanel', () => {
  it('shows the exact approved destination and trusted protected payload before execution', () => {
    renderPanel(null);
    expect(screen.getByText('Approved destination')).toBeInTheDocument();
    expect(screen.getByText('postman-echo.com')).toBeInTheDocument();
    expect(screen.getByText('Requested fields')).toBeInTheDocument();
    expect(screen.getByText('Allowed for egress')).toBeInTheDocument();
    expect(screen.getByText('Trusted synthetic values')).toBeInTheDocument();
    expect(screen.getByText('Protected egress payload')).toBeInTheDocument();
    expect(screen.getAllByText('reason=suspected compromise').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText(/binds the exact destination, trusted normal payload and private-reference set/i)).toBeInTheDocument();
  });

  it('shows REDACT as executable minimization when all required fields remain allowed', () => {
    const redactedAction: ActionProposal = {
      ...action,
      status: 'EVALUATED',
      fields: [...action.fields, 'employee_department'],
      normalPayload: { ...action.normalPayload, employee_department: 'finance' },
    };
    const redactedDecision: PolicyDecision = {
      ...decision,
      actionProposalId: redactedAction.id,
      decision: 'REDACT',
      reasonCode: 'DATA_MINIMIZED',
      redactedFields: ['employee_department'],
      allowedFields: ['incident_id', 'credential_id', 'reason'],
    };
    renderPanel(null, vi.fn(), redactedAction, redactedDecision);
    expect(screen.getByText('Removed before egress')).toBeInTheDocument();
    expect(screen.getByText('employee_department=finance')).toBeInTheDocument();
    const protectedPayload = screen.getByText('Protected egress payload').closest('.field-list');
    expect(protectedPayload).not.toBeNull();
    expect(within(protectedPayload as HTMLElement).queryByText('employee_department=finance')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Authorize credential revocation' })).toBeInTheDocument();
  });

  it('blocks authorization when REDACT removes a required remediation field', () => {
    const currentAction = { ...action, status: 'EVALUATED' as const };
    const currentDecision = { ...decision, decision: 'REDACT' as const, allowedFields: ['incident_id', 'reason'], redactedFields: ['credential_id'] };
    renderPanel(null, vi.fn(), currentAction, currentDecision);
    expect(screen.getByText(/no longer satisfies the action-specific required fields/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Authorize credential revocation' })).not.toBeInTheDocument();
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
    expect(screen.getByRole('alert')).toHaveTextContent(/Destination changed/i);
    expect(screen.getByRole('alert')).toHaveTextContent(/Create a new action/i);
    expect(screen.getByRole('alert')).toHaveTextContent(/authorize it before executing again/i);
  });

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

  it('labels credential revocation completed only after verified read-back', () => {
    renderPanel(execution('COMPLETED', { completedAt: '2026-09-12T18:00:03Z' }));
    expect(screen.getByText('VERIFIED')).toBeInTheDocument();
    expect(screen.getByText('COMPLETED')).toBeInTheDocument();
    expect(screen.getByText(/Independent read-back verified REVOKED/i)).toBeInTheDocument();
  });

  it('shows minimized normal payload and the private notification boundary without plaintext recipient data', () => {
    const notify = notificationAction();
    renderPanel(null, vi.fn(), notify, notificationDecision(notify));
    expect(screen.getByText('verified_email')).toBeInTheDocument();
    expect(screen.getByText('T3N PROTECTED EXECUTION')).toBeInTheDocument();
    expect(screen.getByText('NO')).toBeInTheDocument();
    expect(screen.getByText('DELIVERED')).toBeInTheDocument();
    expect(screen.getAllByText('severity=critical').length).toBeGreaterThanOrEqual(2);
    expect(screen.getByRole('button', { name: 'Execute protected security notification' })).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('{{profile.');
    expect(document.body.textContent).not.toContain('@');
  });

  it('allows notification REDACT only when required fields and verified_email remain allowed', () => {
    const notify = notificationAction('EVALUATED');
    const currentDecision = {
      ...notificationDecision(notify),
      decision: 'REDACT' as const,
      allowedFields: ['incident_id', 'severity', 'summary'],
      redactedFields: ['employee_department'],
    };
    renderPanel(null, vi.fn(), notify, currentDecision);
    expect(screen.getByRole('button', { name: 'Authorize security notification' })).toBeInTheDocument();
  });

  it('blocks notification when verified_email is not policy-allowed', () => {
    const notify = notificationAction('EVALUATED');
    renderPanel(null, vi.fn(), notify, { ...notificationDecision(notify), allowedPrivateRefs: [], redactedPrivateRefs: ['verified_email'] });
    expect(screen.getByRole('alert')).toHaveTextContent(/requires exactly the logical private reference verified_email to remain policy-allowed/i);
    expect(screen.queryByRole('button', { name: 'Authorize security notification' })).not.toBeInTheDocument();
  });

  it('labels notification completion as verified delivery and private resolution', () => {
    const notify = notificationAction('REMEDIATED');
    renderPanel(execution('COMPLETED', { completedAt: '2026-09-12T18:00:03Z' }), vi.fn(), notify, notificationDecision(notify));
    expect(screen.getByText('DELIVERED + RESOLUTION VERIFIED')).toBeInTheDocument();
    expect(screen.getByText(/private recipient was resolved inside T3N/i)).toBeInTheDocument();
    expect(screen.getByText(/plaintext recipient was not returned/i)).toBeInTheDocument();
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
