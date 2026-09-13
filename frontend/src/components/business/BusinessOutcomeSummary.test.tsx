import '@testing-library/jest-dom/vitest';
import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { ActionProposal, AgentAnalysis, Incident, PolicyDecision, RemediationExecution } from '../../services/privacyGuardApi';
import { DEFAULT_ENTERPRISE_SCENARIO } from '../scenarios/scenarioDefinitions';
import { BusinessOutcomeSummary, formatObservedDuration } from './BusinessOutcomeSummary';

const INCIDENT: Incident = {
  id: 'incident-1',
  title: 'Credential compromise',
  severity: 'CRITICAL',
  summary: 'Synthetic compromise',
  source: 'AI_AGENT',
  status: 'OPEN',
  createdAt: '2026-09-13T15:00:00.000Z',
  expiresAt: '2026-09-14T15:00:00.000Z',
  retentionState: 'ACTIVE',
};

const THREAT_ACTION: ActionProposal = {
  id: 'action-threat', incidentId: INCIDENT.id, requestId: 'request-threat', action: 'revoke-credential',
  resource: 'credential:production-security-api', purpose: 'incident-remediation', host: 'attacker.example',
  fields: ['incident_id', 'credential_id', 'api_key'], privateRefs: [], status: 'EVALUATED', createdAt: '2026-09-13T15:00:00.000Z',
};

const SAFE_ACTION: ActionProposal = {
  ...THREAT_ACTION,
  id: 'action-safe', requestId: 'request-safe', host: 'postman-echo.com',
  fields: ['incident_id', 'credential_id', 'reason'],
  normalPayload: { incident_id: 'inc-demo-001', credential_id: 'cred-demo-001', reason: 'suspected compromise' },
  createdAt: '2026-09-13T15:00:01.000Z',
};

const NOTIFY_ACTION: ActionProposal = {
  ...SAFE_ACTION,
  id: 'action-notify', requestId: 'request-notify', action: 'notify-security', resource: 'incident:synthetic',
  purpose: 'incident-notification', fields: ['incident_id', 'severity', 'summary'],
  normalPayload: { incident_id: 'inc-demo-001', severity: 'critical', summary: 'synthetic security incident' },
  privateRefs: ['verified_email'],
};

function policyDecision(action: ActionProposal, value: PolicyDecision['decision'], evaluatedAt = '2026-09-13T15:00:00.420Z'): PolicyDecision {
  const notify = action.action === 'notify-security';
  return {
    id: `decision-${action.id}`,
    actionProposalId: action.id,
    decision: value,
    reasonCode: `${value}_TEST`,
    reason: value,
    allowedFields: value === 'DENY' ? [] : notify ? ['incident_id', 'severity', 'summary'] : ['incident_id', 'credential_id', 'reason'],
    redactedFields: value === 'REDACT' ? ['employee_department'] : [],
    allowedPrivateRefs: value === 'DENY' ? [] : notify ? ['verified_email'] : [],
    redactedPrivateRefs: [],
    requiresHumanAuthorization: value !== 'DENY',
    evaluatedAt,
  };
}

function analysis(value: PolicyDecision['decision']): AgentAnalysis {
  return { provider: 'test', model: 'test-model', incident: INCIDENT, action: THREAT_ACTION, decision: policyDecision(THREAT_ACTION, value) };
}

function execution(action: ActionProposal, state: RemediationExecution['state'], completedAt: string | null = null): RemediationExecution {
  return {
    incidentId: INCIDENT.id,
    actionId: action.id,
    requestId: action.requestId,
    state,
    operationId: 'operation-1',
    verificationAttempts: state === 'COMPLETED' ? 2 : 1,
    startedAt: '2026-09-13T15:00:02.000Z',
    completedAt,
  };
}

function renderSummary(overrides: Partial<Parameters<typeof BusinessOutcomeSummary>[0]> = {}) {
  render(
    <BusinessOutcomeSummary
      scenario={DEFAULT_ENTERPRISE_SCENARIO}
      incident={null}
      selectedAction={null}
      decision={null}
      remediationExecution={null}
      agentAnalysis={null}
      {...overrides}
    />,
  );
}

function section(name: string) {
  const heading = screen.getByRole('heading', { name });
  return within(heading.closest('section') as HTMLElement);
}

function expectValue(label: string, value: string) {
  expect(screen.getByText(label).closest('div')).toHaveTextContent(value);
}

describe('BusinessOutcomeSummary', () => {
  it('does not invent an observed threat or successful result before analysis', () => {
    renderSummary();
    expect(screen.getByRole('status')).toHaveTextContent('No threat has been analyzed yet.');
    expectValue('Policy decision', 'Not yet observed');
    expectValue('Requested destination', 'Not yet observed');
    expectValue('Human authorization', 'Not yet observed');
    expectValue('Approved destination', 'Not yet observed');
    expectValue('External action', 'Not yet observed');
    expectValue('Verification attempts', 'Not yet observed');
    expect(section('Authorized response').getByText('NOT VERIFIED')).toBeInTheDocument();
  });

  it('shows DENY as a blocked proposal and never as completed remediation', () => {
    renderSummary({ incident: INCIDENT, selectedAction: THREAT_ACTION, decision: policyDecision(THREAT_ACTION, 'DENY'), agentAnalysis: analysis('DENY') });
    expect(screen.getByRole('status')).toHaveTextContent('blocked the proposed action before protected egress');
    expect(section('T3N control outcome').getByText('DENY')).toBeInTheDocument();
    expect(section('Authorized response').getAllByText('NOT APPLICABLE')).toHaveLength(2);
    expect(section('Authorized response').getByText('NOT VERIFIED')).toBeInTheDocument();
  });

  it('shows executable REDACT as minimized and still requiring human authorization', () => {
    const action = { ...SAFE_ACTION, status: 'EVALUATED' as const, fields: [...SAFE_ACTION.fields, 'employee_department'], normalPayload: { ...SAFE_ACTION.normalPayload, employee_department: 'finance' } };
    const decision = policyDecision(action, 'REDACT');
    renderSummary({ incident: INCIDENT, selectedAction: action, decision });
    expect(screen.getByRole('status')).toHaveTextContent('minimized the request to an executable minimum');
    expect(section('Authorized response').getByText('REQUIRED')).toBeInTheDocument();
    expect(section('Authorized response').getByText('Not authorized yet')).toBeInTheDocument();
  });

  it('shows ALLOW as requiring human authorization before protected execution', () => {
    const allow = policyDecision(SAFE_ACTION, 'ALLOW', '2026-09-13T15:00:01.420Z');
    renderSummary({ incident: INCIDENT, selectedAction: SAFE_ACTION, decision: allow });
    expect(screen.getByRole('status')).toHaveTextContent('Human authorization is still required');
    expect(section('Authorized response').getByText('REQUIRED')).toBeInTheDocument();
    expect(section('Authorized response').getByText('Not authorized yet')).toBeInTheDocument();
    expectValue('Policy-allowed action', 'revoke-credential');
  });

  it('keeps accepted execution pending until independent verification completes', () => {
    const authorized = { ...SAFE_ACTION, status: 'REMEDIATION_AUTHORIZED' as const };
    renderSummary({ incident: INCIDENT, selectedAction: authorized, decision: policyDecision(authorized, 'ALLOW'), remediationExecution: execution(authorized, 'PENDING_VERIFICATION'), agentAnalysis: analysis('DENY') });
    expect(screen.getByRole('status')).toHaveTextContent('Completion is not yet verified');
    expect(section('Authorized response').getByText('ACCEPTED — VERIFICATION PENDING')).toBeInTheDocument();
    expect(section('Authorized response').getByText('NOT VERIFIED')).toBeInTheDocument();
  });

  it('shows verified revocation state and measured duration only after COMPLETED', () => {
    const remediated = { ...SAFE_ACTION, status: 'REMEDIATED' as const };
    renderSummary({ incident: INCIDENT, selectedAction: remediated, decision: policyDecision(remediated, 'ALLOW'), remediationExecution: execution(remediated, 'COMPLETED', '2026-09-13T15:00:05.850Z'), agentAnalysis: analysis('DENY') });
    expect(screen.getByRole('heading', { name: 'Credential compromise contained' })).toBeInTheDocument();
    expect(section('Authorized response').getByText('REVOKED — VERIFIED')).toBeInTheDocument();
    expect(section('Authorized response').getByText('4.9 s')).toBeInTheDocument();
  });

  it('shows notify-security as requiring human authorization without exposing recipient plaintext', () => {
    const notify = { ...NOTIFY_ACTION, status: 'EVALUATED' as const };
    renderSummary({ incident: INCIDENT, selectedAction: notify, decision: policyDecision(notify, 'ALLOW') });
    expect(section('Authorized response').getByText('REQUIRED')).toBeInTheDocument();
    expect(section('Authorized response').getByText('Not authorized yet')).toBeInTheDocument();
    expect(section('Threat observed').getByText('1 · verified_email')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('@');
    expect(document.body.textContent).not.toContain('{{profile.');
  });

  it('shows DELIVERED VERIFIED only after completed notification read-back', () => {
    const remediated = { ...NOTIFY_ACTION, status: 'REMEDIATED' as const };
    renderSummary({ incident: INCIDENT, selectedAction: remediated, decision: policyDecision(remediated, 'ALLOW'), remediationExecution: execution(remediated, 'COMPLETED', '2026-09-13T15:00:05.850Z') });
    expect(screen.getByRole('heading', { name: 'Security notification delivered' })).toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent(/verified delivery and private recipient resolution/i);
    expect(section('Authorized response').getByText('DELIVERED — VERIFIED')).toBeInTheDocument();
  });

  it('does not estimate time to verified outcome when completedAt is absent', () => {
    const remediated = { ...SAFE_ACTION, status: 'REMEDIATED' as const };
    renderSummary({ incident: INCIDENT, selectedAction: remediated, decision: policyDecision(remediated, 'ALLOW'), remediationExecution: execution(remediated, 'COMPLETED', null) });
    expect(section('Authorized response').getByText('Not verified yet')).toBeInTheDocument();
  });

  it('formats observed durations according to the display rounding rules', () => {
    expect(formatObservedDuration(420)).toBe('420 ms');
    expect(formatObservedDuration(4_850)).toBe('4.9 s');
    expect(formatObservedDuration(61_250)).toBe('1m 1.3s');
  });
});
