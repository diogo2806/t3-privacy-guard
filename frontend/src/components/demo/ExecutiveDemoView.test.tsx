import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type {
  ActionProposal,
  EvidenceBundle,
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
  protectedRemediationReady: true,
  evaluationReady: true,
  agentDid: 'did:t3n:testnet:proposal-agent-123456789',
  executorDid: 'did:t3n:testnet:protected-executor-987654321',
  delegationEffectiveState: 'ACTIVE',
  executorDelegationEffectiveState: 'ACTIVE',
  agentRegistrationState: 'REGISTERED',
} as SystemStatus;

const evidence = {
  metadata: {
    source: 'T3N_TESTNET',
    sourceCommitSha: '0fe48b8aab7917788eb30b81d45e6a11821e48c2',
    sourceTreeClean: true,
    network: 'testnet',
    contractVersion: '0.4.0',
    agentDid: 'did:t3n:testnet:proposal-agent-123456789',
    executorDid: 'did:t3n:testnet:protected-executor-987654321',
  },
  scenarios: [],
  totals: { pass: 12, fail: 0, notRun: 1 },
} as EvidenceBundle;

function renderExecutive(overrides: Partial<React.ComponentProps<typeof ExecutiveDemoView>> = {}) {
  const props: React.ComponentProps<typeof ExecutiveDemoView> = {
    scenario: DEFAULT_ENTERPRISE_SCENARIO,
    systemStatus,
    statusLoading: false,
    agentAnalysis: null,
    selectedAction: null,
    decision: null,
    remediationExecution: null,
    evidence: null,
    evidenceLoading: false,
    evidenceError: null,
    onOpenEvidence: vi.fn(),
    ...overrides,
  };
  return { ...render(<ExecutiveDemoView {...props} />), props };
}

describe('ExecutiveDemoView', () => {
  it('starts without inventing an outcome or live evidence claim', () => {
    renderExecutive();

    expect(screen.getByTestId('executive-observed-outcome')).toHaveTextContent('NOT YET OBSERVED');
    expect(screen.getByTestId('executive-readiness')).toHaveTextContent('INCOMPLETE');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent('Live evidence not loaded/generated');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent(/No PASS state.*is inferred/i);
    expect(screen.getByTestId('executive-step-ai-proposal')).toHaveTextContent('WAITING');
  });

  it.each([
    ['DENY', 'BLOCKED BEFORE PROTECTED EGRESS'],
    ['REDACT', 'MINIMIZATION REQUIRED'],
    ['ALLOW', 'HUMAN AUTHORIZATION REQUIRED'],
  ] as const)('projects %s without advancing later authority steps', (type, outcome) => {
    renderExecutive({ selectedAction: baseAction, decision: decision(type) });

    expect(screen.getByTestId('executive-observed-outcome')).toHaveTextContent(outcome);
    expect(screen.getByTestId('executive-step-t3n-policy')).toHaveTextContent(type);
    expect(screen.getByTestId('executive-step-executor')).not.toHaveTextContent('EXECUTED');
    expect(screen.getByTestId('executive-step-verify')).toHaveTextContent('WAITING');
  });

  it('shows human authorization as observed but does not claim execution', () => {
    renderExecutive({
      selectedAction: { ...baseAction, host: 'postman-echo.com', status: 'REMEDIATION_AUTHORIZED' },
      decision: decision('ALLOW'),
    });

    expect(screen.getByTestId('executive-observed-outcome')).toHaveTextContent('AUTHORIZED / NOT EXECUTED');
    expect(screen.getByTestId('executive-step-human')).toHaveTextContent('AUTHORIZED');
    expect(screen.getByTestId('executive-step-executor')).toHaveTextContent('NOT STARTED');
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

  it('shows compact proof only from a valid evidence bundle and keeps identity/delegation claims explicit', () => {
    renderExecutive({ evidence });

    expect(screen.getByTestId('executive-readiness')).toHaveTextContent('T3N LIVE / READY');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent('12 PASS / 0 FAIL / 1 NOT RUN');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent('0fe48b8a…');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent('SEPARATE');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent('CONFIRMED');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent('REGISTERED');
    expect(screen.getByTestId('executive-proof')).toHaveTextContent(/NOT RUN is not proof/i);
  });

  it('navigates only to technical evidence and keeps the Screen Manual accessible', async () => {
    const user = userEvent.setup();
    const onOpenEvidence = vi.fn();
    renderExecutive({ evidence, onOpenEvidence });

    await user.click(screen.getByRole('button', { name: 'Open technical evidence' }));
    expect(onOpenEvidence).toHaveBeenCalledTimes(1);
    const manual = screen.getByRole('button', { name: 'Open Screen Manual' });
    expect(manual).toHaveAttribute('title', 'Manual da Tela / Screen Manual');
  });
});
