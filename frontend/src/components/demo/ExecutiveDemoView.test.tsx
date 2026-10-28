import '@testing-library/jest-dom/vitest';
import type { ComponentProps } from 'react';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type {
  ActionProposal,
  PolicyDecision,
  RemediationExecution,
  SystemStatus,
} from '../../services/privacyGuardApi';
import { DEFAULT_ENTERPRISE_SCENARIO } from '../scenarios/scenarioDefinitions';
import { ExecutiveDemoView } from './ExecutiveDemoView';

const baseAction: ActionProposal = {
  id: 'action-1',
  incidentId: 'incident-1',
  requestId: 'request-1',
  action: 'revoke-credential',
  resource: 'credential:production-security-api',
  purpose: 'security-remediation',
  host: 'attacker.example',
  fields: ['incident_id', 'credential_id', 'reason', 'api_key'],
  privateRefs: [],
  status: 'EVALUATED',
  createdAt: '2026-09-13T20:00:00.000Z',
};

function decision(type: PolicyDecision['decision']): PolicyDecision {
  return {
    id: `decision-${type}`,
    actionProposalId: baseAction.id,
    decision: type,
    reasonCode: type === 'ALLOW' ? 'POLICY_ALLOWED' : type === 'REDACT' ? 'DATA_MINIMIZATION_REQUIRED' : 'UNAPPROVED_DESTINATION',
    reason: 'Observed policy result',
    allowedFields: type === 'DENY' ? [] : ['incident_id', 'credential_id', 'reason'],
    redactedFields: type === 'REDACT' ? ['api_key'] : [],
    allowedPrivateRefs: [],
    redactedPrivateRefs: [],
    policyVersion: '2026-09-13.1',
    evaluatedAt: '2026-09-13T20:00:00.420Z',
  };
}

function execution(state: RemediationExecution['state']): RemediationExecution {
  return {
    incidentId: baseAction.incidentId,
    actionId: baseAction.id,
    requestId: baseAction.requestId,
    state,
    verificationAttempts: state === 'COMPLETED' ? 1 : 0,
    startedAt: '2026-09-13T20:01:00.000Z',
    completedAt: state === 'COMPLETED' ? '2026-09-13T20:01:02.000Z' : null,
  };
}

const systemStatus = {
  network: 'selfhosted',
  protectedRemediationReady: true,
  evaluationReady: true,
  enterpriseIntegrationState: 'READY',
  enterpriseIntegrationReady: true,
  agentDid: 'agent:proposal',
  executorDid: 'agent:executor',
  delegationEffectiveState: 'ACTIVE',
  executorDelegationEffectiveState: 'ACTIVE',
} as SystemStatus;

type ExecutiveDemoProps = ComponentProps<typeof ExecutiveDemoView>;

function renderExecutive(overrides: Partial<ExecutiveDemoProps> = {}) {
  const props: ExecutiveDemoProps = {
    scenario: DEFAULT_ENTERPRISE_SCENARIO,
    systemStatus,
    statusLoading: false,
    agentAnalysis: null,
    selectedAction: null,
    decision: null,
    remediationExecution: null,
    ...overrides,
  };
  return { ...render(<ExecutiveDemoView {...props} />), props };
}

function expectProofFact(label: string, value: string) {
  const fact = screen.getByText(label).closest('div');
  expect(fact).not.toBeNull();
  expect(fact).toHaveTextContent(value);
}

describe('ExecutiveDemoView', () => {
  it('leads with enterprise value before explaining the authority mechanism', () => {
    renderExecutive();

    const surface = screen.getByTestId('executive-demo-view');
    const valueHeadline = 'Use AI agents in sensitive workflows without giving the model security authority.';
    const mechanism = 'AI can propose. Policy decides. Humans authorize. Guard runtime executes.';
    expect(screen.getByRole('heading', { level: 1, name: valueHeadline })).toBeInTheDocument();
    expect(screen.getByText(/Keep private data, policy decisions and critical actions outside the model/i)).toBeInTheDocument();
    expect(screen.getByText(mechanism)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Business risk' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Observed outcome' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Observed runtime outcomes' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Trust path' })).toBeInTheDocument();
    expect((surface.textContent ?? '').indexOf(valueHeadline)).toBeLessThan((surface.textContent ?? '').indexOf(mechanism));
  });

  it('starts without inventing an outcome or decision', () => {
    renderExecutive();

    expect(screen.getByTestId('executive-observed-outcome')).toHaveTextContent('NOT YET OBSERVED');
    expect(screen.getByTestId('executive-step-ai-proposal')).toHaveTextContent('WAITING');
    expect(screen.getByTestId('executive-step-guard-runtime-policy')).toHaveTextContent('No Guard runtime decision observed yet.');
    expectProofFact('Policy version', 'NOT OBSERVED');
  });

  it.each([
    ['DENY', 'BLOCKED BEFORE PROTECTED EGRESS'],
    ['REDACT', 'MINIMIZATION REQUIRED'],
    ['ALLOW', 'HUMAN AUTHORIZATION REQUIRED'],
  ] as const)('projects %s without advancing later authority steps', (type, outcome) => {
    renderExecutive({ selectedAction: baseAction, decision: decision(type) });

    expect(screen.getByTestId('executive-observed-outcome')).toHaveTextContent(outcome);
    expect(screen.getByTestId('executive-step-guard-runtime-policy')).toHaveTextContent(type);
    expect(screen.getByTestId('executive-step-executor')).toHaveTextContent('NOT EXECUTED');
    expect(screen.getByTestId('executive-step-executor')).not.toHaveClass('executive-tone-success');
    expect(screen.getByTestId('executive-step-verify')).toHaveTextContent('WAITING');
    expectProofFact('Policy version', '2026-09-13.1');
  });

  it('shows human authorization as observed but does not claim execution or verification', () => {
    renderExecutive({
      selectedAction: { ...baseAction, host: 'postman-echo.com', status: 'REMEDIATION_AUTHORIZED' },
      decision: decision('ALLOW'),
    });

    expect(screen.getByTestId('executive-observed-outcome')).toHaveTextContent('AUTHORIZED / NOT EXECUTED');
    expect(screen.getByTestId('executive-step-human')).toHaveTextContent('AUTHORIZED');
    expect(screen.getByTestId('executive-step-executor')).toHaveTextContent('NOT STARTED');
    expect(screen.getByTestId('executive-step-verify')).toHaveTextContent('NOT VERIFIED YET');
  });

  it.each([
    ['PENDING_VERIFICATION', 'ACCEPTED / NOT VERIFIED', 'PENDING'],
    ['UNVERIFIED', 'UNVERIFIED — COMPLETION NOT CLAIMED', 'UNVERIFIED'],
    ['FAILED', 'FAILED — NO VERIFIED OUTCOME', 'UNVERIFIED'],
    ['COMPLETED', 'VERIFIED EXTERNAL STATE: REVOKED', 'VERIFIED'],
  ] as const)('keeps remediation state %s semantically distinct', (state, outcome, verification) => {
    renderExecutive({
      selectedAction: { ...baseAction, host: 'postman-echo.com', status: 'REMEDIATION_AUTHORIZED' },
      decision: decision('ALLOW'),
      remediationExecution: execution(state),
    });

    expect(screen.getByTestId('executive-observed-outcome')).toHaveTextContent(outcome);
    expect(screen.getByTestId('executive-step-verify')).toHaveTextContent(verification);
  });

  it('derives LIVE / READY from live status only and keeps runtime claims explicit', () => {
    renderExecutive();

    expect(screen.getByTestId('executive-readiness')).toHaveTextContent('GUARD RUNTIME LIVE / READY');
    expectProofFact('Policy evaluation', 'READY');
    expectProofFact('Protected remediation', 'READY');
    expectProofFact('Identity separation', 'SEPARATE');
    expectProofFact('Effective access', 'CONFIRMED');
    expectProofFact('Enterprise integration', 'READY');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent(/Enterprise integration READY does not prove external service success/i);
    expect(screen.getByTestId('executive-proof')).not.toHaveTextContent(/\bPASS\b|evidence bundle|Agent Card|registration/);
  });

  it('shows checking while the live status is loading', () => {
    renderExecutive({ statusLoading: true });

    expect(screen.getByTestId('executive-readiness')).toHaveTextContent('CHECKING RUNTIME');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent('Checking live status…');
  });

  it('shows NOT OBSERVED for runtime proof facts when SystemStatus is unavailable', () => {
    renderExecutive({ systemStatus: null });

    expect(screen.getByTestId('executive-readiness')).toHaveTextContent('NOT READY');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent('Live status not loaded');
    expectProofFact('Policy evaluation', 'NOT OBSERVED');
    expectProofFact('Identity separation', 'NOT OBSERVED');
    expectProofFact('Effective access', 'NOT OBSERVED');
    expectProofFact('Enterprise integration', 'NOT OBSERVED');
  });

  it('does not label runtime ready when protected remediation is not ready', () => {
    renderExecutive({
      systemStatus: { ...systemStatus, protectedRemediationReady: false, executorDelegationEffectiveState: 'DENIED' } as SystemStatus,
    });

    expect(screen.getByTestId('executive-readiness')).toHaveTextContent('INCOMPLETE');
    expectProofFact('Protected remediation', 'NOT READY');
    expectProofFact('Effective access', 'DENIED');
  });

  it('does not label runtime ready when enterprise integration is incomplete', () => {
    renderExecutive({
      systemStatus: { ...systemStatus, enterpriseIntegrationState: 'INCOMPLETE', enterpriseIntegrationReady: false } as SystemStatus,
    });

    expect(screen.getByTestId('executive-readiness')).toHaveTextContent('INCOMPLETE');
    expectProofFact('Enterprise integration', 'INCOMPLETE');
  });

  it('flags a shared proposal and executor identity', () => {
    renderExecutive({ systemStatus: { ...systemStatus, executorDid: systemStatus.agentDid } as SystemStatus });

    expectProofFact('Identity separation', 'IDENTITY COLLISION');
  });

  it('offers only the Screen Manual as an action', () => {
    renderExecutive();

    expect(screen.getAllByRole('button')).toHaveLength(1);
    const manual = screen.getByRole('button', { name: 'Open Screen Manual' });
    expect(manual).toHaveAttribute('title', 'Open Screen Manual');
  });
});
