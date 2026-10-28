import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ActionProposal, PolicyDecision, RemediationExecution } from '../../services/privacyGuardApi';
import { SELF_HOSTED_RUNTIME, TrustRuntimeContext } from '../../services/trustRuntime';
import { RemediationPanel } from './RemediationPanel';

const notifyAction: ActionProposal = {
  id: 'action-notify', incidentId: 'incident-1', requestId: 'request-notify', action: 'notify-security',
  resource: 'incident:test', purpose: 'incident-notification', host: 'postman-echo.com',
  fields: ['incident_id', 'severity', 'summary'],
  normalPayload: { incident_id: 'inc-demo-001', severity: 'critical', summary: 'synthetic security incident' },
  privateRefs: ['verified_email'], status: 'REMEDIATION_AUTHORIZED', createdAt: '2026-10-28T18:00:00Z',
  remediationAuthorizedBy: 'ops-reviewer', remediationAuthorizedAt: '2026-10-28T18:00:01Z',
};

const notifyDecision: PolicyDecision = {
  id: 'decision-notify', actionProposalId: notifyAction.id, decision: 'ALLOW', reasonCode: 'POLICY_ALLOW', reason: 'Allowed',
  allowedFields: notifyAction.fields, redactedFields: [], allowedPrivateRefs: ['verified_email'], redactedPrivateRefs: [], evaluatedAt: '2026-10-28T18:00:01Z',
};

function renderSelfHosted(execution: RemediationExecution | null) {
  render(
    <TrustRuntimeContext.Provider value={SELF_HOSTED_RUNTIME}>
      <RemediationPanel action={notifyAction} decision={notifyDecision} execution={execution} busy={false} onAuthorize={vi.fn()} onExecute={vi.fn()} onVerify={vi.fn()} />
    </TrustRuntimeContext.Provider>,
  );
}

afterEach(() => {
  cleanup();
});

describe('RemediationPanel on the self-hosted guard-runtime', () => {
  it('shows the guard-runtime resolution boundary and proof check for private notification', () => {
    renderSelfHosted(null);
    expect(screen.getByText('GUARD RUNTIME PROTECTED EXECUTION')).toBeInTheDocument();
    expect(screen.getByText('Guard runtime execution proof check')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'Guard runtime payload minimization' })).toBeInTheDocument();
    expect(screen.getByText(/Guard runtime resolves the private recipient inside protected execution/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('T3N');
  });

  it('attributes verified private-recipient resolution to Guard runtime', () => {
    renderSelfHosted({
      incidentId: notifyAction.incidentId, actionId: notifyAction.id, requestId: notifyAction.requestId, state: 'COMPLETED',
      httpCode: 202, operationId: 'op-1', verificationAttempts: 1, startedAt: '2026-10-28T18:00:02Z', completedAt: '2026-10-28T18:00:03Z',
    });
    expect(screen.getByText(/confirmed private-recipient resolution inside Guard runtime/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('T3N');
  });
});
