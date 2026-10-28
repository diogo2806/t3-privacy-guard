import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { PolicyDecision } from '../../services/privacyGuardApi';
import { SELF_HOSTED_RUNTIME, TrustRuntimeContext } from '../../services/trustRuntime';
import { DecisionPanel } from './DecisionPanel';

const decision: PolicyDecision = {
  id: 'd1',
  actionProposalId: 'a1',
  decision: 'DENY',
  reasonCode: 'UNEXPECTED_EGRESS',
  reason: 'The requested destination is not approved',
  allowedFields: [],
  redactedFields: ['api_key'],
  allowedPrivateRefs: [],
  redactedPrivateRefs: [],
  policyVersion: '2026-10-28.1',
  policyHash: 'b'.repeat(64),
  requiresHumanAuthorization: true,
  evaluatedAt: '2026-10-28T12:00:00Z',
};

function renderSelfHosted(current: PolicyDecision | null) {
  render(<TrustRuntimeContext.Provider value={SELF_HOSTED_RUNTIME}><DecisionPanel decision={current} /></TrustRuntimeContext.Provider>);
}

afterEach(() => {
  cleanup();
});

describe('DecisionPanel on the self-hosted guard-runtime', () => {
  it('attributes the awaiting state to Guard runtime', () => {
    renderSelfHosted(null);
    expect(screen.getByText('Guard runtime policy decision')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Awaiting evaluation' })).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('T3N');
  });

  it('attributes an observed decision to Guard runtime', () => {
    renderSelfHosted(decision);
    expect(screen.getByText('Guard runtime policy decision')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'DENY' })).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('T3N');
  });

  it('keeps the T3N copy when no runtime provider is present', () => {
    render(<DecisionPanel decision={decision} />);
    expect(screen.getByText('T3N policy decision')).toBeInTheDocument();
    expect(screen.queryByText('Guard runtime policy decision')).not.toBeInTheDocument();
  });
});
