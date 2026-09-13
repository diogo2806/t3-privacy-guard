import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { privacyGuardApi, type AuditEvidence, type AuditEvent } from '../../services/privacyGuardApi';
import { AuditTrail } from './AuditTrail';

const localEvent: AuditEvent = {
  id: 'local-1',
  incidentId: 'incident-1',
  type: 'POLICY_DECISION',
  message: 'Policy decision ALLOW with reason POLICY_ALLOW',
  createdAt: '2026-09-12T20:00:00Z',
};

const matchedEvidence: AuditEvidence = {
  localEvents: [{
    ...localEvent,
    status: 'MATCHED',
    t3nSequence: 42,
    t3nFunction: 'evaluate-action',
    matchedSequence: 42,
  }],
  t3nEvents: [{
    sequence: 42,
    hash: 'hash-42',
    timestamp: '2026-09-12T20:00:01Z',
    callerType: 'agent',
    actorDid: 'did:t3n:agent',
    onBehalfOfDid: 'did:t3n:tenant',
    contractId: 'z:tenant:privacy-guard',
    function: 'evaluate-action',
    outcome: 'success',
    status: 'MATCHED',
  }],
  provenance: {
    localAvailable: true,
    t3nAvailable: true,
    t3nComplete: true,
    matched: 1,
    unmatched: 0,
    localOnly: 0,
    t3nOnly: 0,
    message: 'T3N activity is available. Reconciliation requires exact sequence, hash, contract, function and the canonical actor for that function.',
  },
  nextSequence: null,
  limit: 100,
};

afterEach(() => vi.restoreAllMocks());

describe('AuditTrail', () => {
  it('keeps local and T3N sources visually distinct and explains the function-specific actor boundary', async () => {
    vi.spyOn(privacyGuardApi, 'auditEvidence').mockResolvedValue(matchedEvidence);
    render(<AuditTrail events={[localEvent]} />);

    expect(await screen.findByText('T3N Activity Log')).toBeInTheDocument();
    expect(screen.getByText('Local business audit')).toBeInTheDocument();
    expect(screen.getByText(/Proposal Agent for evaluation, Protected Executor for execution and verification/)).toBeInTheDocument();
    expect(screen.getAllByText('Matched')).toHaveLength(3);
    expect(screen.getByText('Sequence 42 · success')).toBeInTheDocument();
    expect(screen.getByText(/Expected T3N function:/)).toBeInTheDocument();
    expect(screen.getByText('did:t3n:agent')).toBeInTheDocument();
  });

  it('preserves local business audit and shows the degraded provenance copy', async () => {
    vi.spyOn(privacyGuardApi, 'auditEvidence').mockResolvedValue({
      localEvents: [{ ...localEvent, status: 'UNMATCHED', t3nFunction: 'evaluate-action' }],
      t3nEvents: [],
      provenance: {
        localAvailable: true,
        t3nAvailable: false,
        t3nComplete: false,
        matched: 0,
        unmatched: 1,
        localOnly: 0,
        t3nOnly: 0,
        message: 'T3N activity temporarily unavailable. Local business audit remains available; network provenance was not verified.',
      },
      nextSequence: null,
      limit: 100,
    });
    render(<AuditTrail events={[localEvent]} />);

    expect(await screen.findByText(/T3N activity temporarily unavailable/)).toBeInTheDocument();
    expect(screen.getByText('Policy decision ALLOW with reason POLICY_ALLOW')).toBeInTheDocument();
    expect(screen.getByText('T3N unavailable')).toBeInTheDocument();
  });

  it('refreshes provenance without mutating the local event list', async () => {
    const spy = vi.spyOn(privacyGuardApi, 'auditEvidence').mockResolvedValue(matchedEvidence);
    const user = userEvent.setup();
    render(<AuditTrail events={[localEvent]} />);
    await screen.findByText('Sequence 42 · success');

    await user.click(screen.getByRole('button', { name: 'Refresh provenance' }));

    expect(spy).toHaveBeenCalledTimes(2);
    expect(screen.getByText('Policy decision ALLOW with reason POLICY_ALLOW')).toBeInTheDocument();
  });
});
