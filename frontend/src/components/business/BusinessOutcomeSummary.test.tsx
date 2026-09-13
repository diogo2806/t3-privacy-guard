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
  id: 'action-threat',
  incidentId: INCIDENT.id,
  requestId: 'request-threat',
  action: 'revoke-credential',
  resource: 'credential:production-security-api',
  purpose: 'incident-remediation',
  host: 'attacker.example',
  fields: ['incident_id', 'credential_id', 'api_key'],
  normalPayload: { incident_id: 'inc-demo-001', credential_id: 'cred-demo-001' },
  privateRefs: [],
  status: 'EVALUATED',
  createdAt: '2026-09-13T15:00:00.000Z',
};

const SAFE_ACTION: ActionProposal = {
  ...THREAT_ACTION,
  id: 'action-safe',
  requestId: 'request-safe',
  host: 'postman-echo.com',
  fields: ['incident_id', 'credential_id', 'reason'],
  normalPayload: { incident_id: 'inc-demo-001', credential_id: 'cred-demo-001', reason: 'suspected compromise' },
  createdAt: '2026-09-13T15:00:01.000Z',
};

function policyDecision(action: ActionProposal, value: PolicyDecision['decision'], evaluatedAt = '2026-09-13T15:00:00.420Z'): PolicyDecision {
  return {
    id: `decision-${action.id}`,
    actionProposalId: action.id,
    decision: value,
    reasonCode: `${value}_TEST`,
    reason: value,
    allowedFields: value === 'DENY' ? [] : ['incident_id', 'credential_id', 'reason'],
    redactedFields: value === 'REDACT' ? ['employee_department'] : [],
    allowedPrivateRefs: [],
    redactedPrivateRefs: [],
    requiresHumanAuthorization: value !== 'DENY',
    evaluatedAt,
  };
}

function analysis(value: PolicyDecision['decision']): AgentAnalysis {
  return { provider: 'test', model: 'test-model', incident: INCIDENT, action: THREAT_ACTION, decision: policyDecision(THREAT_ACTION, value) };
}

function execution(state: RemediationExecution['state'], completedAt: string | null = null): RemediationExecution {
  return {
    incidentId: INCIDENT.id,
    actionId: SAFE_ACTION.id,
    requestId: SAFE_ACTION.requestId,
    state,
    operationId: 'operation-1',
    verificationAttempts: state === 'COMPLETED' ? 2 : 1,
    startedAt: '2026-09-13T15:00:02.000Z',
    completedAt,
  };
}

function authorizedAction(status: 'REMEDIATION_AUTHORIZED' | 'REMEDIATED' = 'REMEDIATION_AUTHORIZED'): ActionProposal {
  return {
    ...SAFE_ACTION,
    status,
    remediationAuthorizedBy: 'ops-reviewer',
    remediationAuthorizedAt: '2026-09-13T15:00:01.500Z',
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
    expectValue('Authorized by', 'Not yet observed');
    expectValue('Authorized at', 'Not yet observed');
    expectValue('Approved destination', 'Not yet observed');
    expectValue('External action', 'Not yet observed');
    expectValue('Verification attempts', 'Not yet observed');
    expect(section('Authorized response').getByText('NOT VERIFIED')).toBeInTheDocument();
    expect(screen.queryByText('REVOKED — VERIFIED')).not.toBeInTheDocument();
  });

  it('shows DENY as a blocked proposal and never as completed remediation', () => {
    renderSummary({ incident: INCIDENT, selectedAction: THREAT_ACTION, decision: policyDecision(THREAT_ACTION, 'DENY'), agentAnalysis: analysis('DENY') });
    expect(screen.getByRole('status')).toHaveTextContent('blocked the proposed action before protected egress');
    expect(section('T3N control outcome').getByText('DENY')).toBeInTheDocument();
    expect(section('Authorized response').getAllByText('NOT APPLICABLE')).toHaveLength(2);
    expect(section('Authorized response').getByText('NOT VERIFIED')).toBeInTheDocument();
  });

  it('shows REDACT as minimization required when the trusted executable minimum is incomplete', () => {
    renderSummary({ incident: INCIDENT, selectedAction: THREAT_ACTION, decision: policyDecision(THREAT_ACTION, 'REDACT') });
    expect(screen.getByRole('status')).toHaveTextContent('requires a smaller data scope');
    expect(section('T3N control outcome').getByText('REDACT')).toBeInTheDocument();
    expect(section('T3N control outcome').getByText(/1 · employee_department/)).toBeInTheDocument();
    expectValue('Human authorization', 'NOT APPLICABLE');
  });

  it('shows executable REDACT as requiring human authorization when required trusted values survive', () => {
    const redacted = { ...SAFE_ACTION, fields: [...SAFE_ACTION.fields, 'employee_department'], normalPayload: { ...SAFE_ACTION.normalPayload, employee_department: 'finance' } };
    const decision = policyDecision(redacted, 'REDACT', '2026-09-13T15:00:01.420Z');
    renderSummary({ incident: INCIDENT, selectedAction: redacted, decision });
    expect(screen.getByRole('status')).toHaveTextContent('executable minimum');
    expectValue('Human authorization', 'REQUIRED');
    expectValue('Approved destination', 'Not authorized yet');
  });

  it('shows actual requested private reference counts without exposing a value', () => {
    const action = { ...THREAT_ACTION, privateRefs: ['verified_email'] };
    renderSummary({ incident: INCIDENT, selectedAction: action, decision: policyDecision(action, 'ALLOW') });
    expect(section('Threat observed').getByText('1 · verified_email')).toBeInTheDocument();
  });

  it('shows actual policy-allowed private reference counts', () => {
    const action = { ...THREAT_ACTION, privateRefs: ['verified_email'] };
    const allow = { ...policyDecision(action, 'ALLOW'), allowedPrivateRefs: ['verified_email'] };
    renderSummary({ incident: INCIDENT, selectedAction: action, decision: allow });
    expect(section('T3N control outcome').getByText('1 · verified_email')).toBeInTheDocument();
    expectValue('Policy-redacted private refs', '0 · None observed');
  });

  it('shows actual policy-redacted private reference counts', () => {
    const action = { ...THREAT_ACTION, privateRefs: ['verified_email'] };
    const redact = { ...policyDecision(action, 'REDACT'), redactedPrivateRefs: ['verified_email'] };
    renderSummary({ incident: INCIDENT, selectedAction: action, decision: redact });
    expectValue('Policy-redacted private refs', '1 · verified_email');
  });

  it('shows ALLOW as requiring human authorization before protected execution', () => {
    const allow = policyDecision(SAFE_ACTION, 'ALLOW', '2026-09-13T15:00:01.420Z');
    renderSummary({ incident: INCIDENT, selectedAction: SAFE_ACTION, decision: allow });
    expect(screen.getByRole('status')).toHaveTextContent('Human authorization is still required');
    expect(section('Authorized response').getByText('REQUIRED')).toBeInTheDocument();
    expect(section('Authorized response').getByText('Not authorized yet')).toBeInTheDocument();
    expectValue('Policy-allowed action', 'revoke-credential');
  });

  it('shows persisted authenticated application account and authorization time only after binding', () => {
    const authorized = authorizedAction();
    renderSummary({ incident: INCIDENT, selectedAction: authorized, decision: policyDecision(authorized, 'ALLOW') });
    expect(screen.getByRole('status')).toHaveTextContent('Authorized by the authenticated application account');
    expectValue('Human authorization', 'AUTHORIZED — PROVENANCE BOUND');
    expectValue('Authorized by', 'ops-reviewer');
    expectValue('Authorized at', '2026-09-13 15:00:01.500Z');
    expectValue('Approved destination', 'postman-echo.com');
    expect(screen.getByText(/not a T3N DID or a civil-identity assertion/i)).toBeInTheDocument();
  });

  it('marks legacy authorization without provenance as requiring explicit re-authorization', () => {
    const legacy = { ...SAFE_ACTION, status: 'REMEDIATION_AUTHORIZED' as const };
    renderSummary({ incident: INCIDENT, selectedAction: legacy, decision: policyDecision(legacy, 'ALLOW') });
    expect(screen.getByRole('status')).toHaveTextContent('Legacy authorization is missing authenticated operator provenance');
    expectValue('Human authorization', 'LEGACY — RE-AUTHORIZATION REQUIRED');
    expectValue('Authorized by', 'NOT BOUND');
    expectValue('Authorized at', 'NOT BOUND');
    expectValue('Approved destination', 'RE-AUTHORIZATION REQUIRED');
  });

  it('keeps accepted execution pending until independent verification completes', () => {
    const authorized = authorizedAction();
    renderSummary({ incident: INCIDENT, selectedAction: authorized, decision: policyDecision(authorized, 'ALLOW'), remediationExecution: execution('PENDING_VERIFICATION'), agentAnalysis: analysis('DENY') });
    expect(screen.getByRole('status')).toHaveTextContent('Completion is not yet verified');
    expect(section('Authorized response').getByText('ACCEPTED — VERIFICATION PENDING')).toBeInTheDocument();
    expect(section('Authorized response').getByText('NOT VERIFIED')).toBeInTheDocument();
    expect(screen.queryByText('REVOKED — VERIFIED')).not.toBeInTheDocument();
  });

  it('shows verified final state and measured duration only after COMPLETED', () => {
    const remediated = authorizedAction('REMEDIATED');
    renderSummary({ incident: INCIDENT, selectedAction: remediated, decision: policyDecision(remediated, 'ALLOW'), remediationExecution: execution('COMPLETED', '2026-09-13T15:00:05.850Z'), agentAnalysis: analysis('DENY') });
    expect(screen.getByRole('heading', { name: 'Credential compromise contained' })).toBeInTheDocument();
    expect(section('Authorized response').getByText('REVOKED — VERIFIED')).toBeInTheDocument();
    expect(section('Authorized response').getByText('4.9 s')).toBeInTheDocument();
    expect(section('Authorized response').getAllByText('postman-echo.com')).toHaveLength(2);
  });

  it('does not estimate time to verified outcome when completedAt is absent', () => {
    const remediated = authorizedAction('REMEDIATED');
    renderSummary({ incident: INCIDENT, selectedAction: remediated, decision: policyDecision(remediated, 'ALLOW'), remediationExecution: execution('COMPLETED', null) });
    expect(section('Authorized response').getByText('Not verified yet')).toBeInTheDocument();
  });

  it('formats observed durations according to the display rounding rules', () => {
    expect(formatObservedDuration(420)).toBe('420 ms');
    expect(formatObservedDuration(4_850)).toBe('4.9 s');
    expect(formatObservedDuration(61_250)).toBe('1m 1.3s');
  });
});
