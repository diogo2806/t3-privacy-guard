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
    runtimeSequence: 42,
    runtimeFunction: 'evaluate-action',
    matchedSequence: 42,
  }],
  runtimeEvents: [{
    sequence: 42,
    hash: 'hash-42',
    timestamp: '2026-09-12T20:00:01Z',
    callerType: 'agent',
    actorDid: 'agent:proposal',
    onBehalfOfDid: 'tenant:acme',
    contractId: 'privacy-guard',
    function: 'evaluate-action',
    outcome: 'success',
    status: 'MATCHED',
  }],
  provenance: {
    localAvailable: true,
    runtimeAvailable: true,
    runtimeComplete: true,
    matched: 1,
    unmatched: 0,
    localOnly: 0,
    runtimeOnly: 0,
    message: 'guard-runtime activity is available. Reconciliation requires exact sequence, hash, contract, function and the canonical actor for that function.',
  },
  integrity: {
    state: 'VERIFIED',
    eventsChecked: 1,
    head: 'a'.repeat(64),
    version: 'v1',
    detail: 'HMAC chain verified.',
  },
  nextSequence: null,
  limit: 100,
};

afterEach(() => vi.restoreAllMocks());

describe('AuditTrail', () => {
  it('shows local HMAC integrity independently from Guard runtime provenance and preserves the actor boundary', async () => {
    vi.spyOn(privacyGuardApi, 'auditEvidence').mockResolvedValue(matchedEvidence);
    render(<AuditTrail events={[localEvent]} />);

    expect(await screen.findByText('Guard runtime Activity Log')).toBeInTheDocument();
    expect(screen.getByText('Sanitized business audit')).toBeInTheDocument();
    expect(screen.getByLabelText('Local audit integrity: Integrity verified')).toBeInTheDocument();
    expect(screen.getByText(/Local HMAC integrity and Guard runtime activity provenance are independent signals/)).toBeInTheDocument();
    expect(screen.getByText(/Proposal Agent for evaluation, Protected Executor for execution and verification/)).toBeInTheDocument();
    expect(screen.getAllByText('Matched')).toHaveLength(3);
    expect(screen.getByText('Sequence 42 · success')).toBeInTheDocument();
    expect(screen.getByText(/Expected Guard runtime function:/)).toBeInTheDocument();
    expect(screen.getByText('agent:proposal')).toBeInTheDocument();
  });

  it('labels runtime activity without a local match as runtime only', async () => {
    vi.spyOn(privacyGuardApi, 'auditEvidence').mockResolvedValue({
      ...matchedEvidence,
      runtimeEvents: [{ ...matchedEvidence.runtimeEvents[0], status: 'RUNTIME_ONLY' }],
      provenance: { ...matchedEvidence.provenance, matched: 0, runtimeOnly: 1 },
    });
    render(<AuditTrail events={[localEvent]} />);

    expect(await screen.findByText('Sequence 42 · success')).toBeInTheDocument();
    expect(screen.getAllByText('Runtime only')).toHaveLength(2);
    expect(screen.getByText('Runtime only', { selector: '.audit-status' })).toHaveClass('audit-status-runtime-only');
  });

  it('keeps verified local integrity positive when Guard runtime provenance is unavailable', async () => {
    vi.spyOn(privacyGuardApi, 'auditEvidence').mockResolvedValue({
      localEvents: [{ ...localEvent, status: 'UNMATCHED', runtimeFunction: 'evaluate-action' }],
      runtimeEvents: [],
      provenance: {
        localAvailable: true,
        runtimeAvailable: false,
        runtimeComplete: false,
        matched: 0,
        unmatched: 1,
        localOnly: 0,
        runtimeOnly: 0,
        message: 'guard-runtime activity temporarily unavailable. Local business audit remains available; runtime provenance was not verified.',
      },
      integrity: {
        state: 'VERIFIED',
        eventsChecked: 1,
        head: 'b'.repeat(64),
        version: 'v1',
        detail: 'HMAC chain verified.',
      },
      nextSequence: null,
      limit: 100,
    });
    render(<AuditTrail events={[localEvent]} />);

    expect(await screen.findByText(/guard-runtime activity temporarily unavailable/)).toBeInTheDocument();
    expect(screen.getByLabelText('Local audit integrity: Integrity verified')).toBeInTheDocument();
    expect(screen.getByText('Policy decision ALLOW with reason POLICY_ALLOW')).toBeInTheDocument();
    expect(screen.getByText('Runtime unavailable')).toBeInTheDocument();
    expect(screen.getByText(/Runtime provenance was not verified/)).toBeInTheDocument();
  });

  it('shows broken local integrity as an alert even when the Guard runtime event matches', async () => {
    vi.spyOn(privacyGuardApi, 'auditEvidence').mockResolvedValue({
      ...matchedEvidence,
      integrity: {
        state: 'BROKEN',
        eventsChecked: 0,
        head: null,
        version: 'v1',
        detail: 'Stored content no longer matches its MAC.',
      },
    });
    render(<AuditTrail events={[localEvent]} />);

    const integrity = await screen.findByLabelText('Local audit integrity: Integrity broken');
    expect(integrity).toHaveAttribute('role', 'alert');
    expect(screen.getByText(/Protected changes are blocked/)).toBeInTheDocument();
    expect(screen.getByText('Sequence 42 · success')).toBeInTheDocument();
  });

  it('refreshes audit evidence without mutating the local event list', async () => {
    const spy = vi.spyOn(privacyGuardApi, 'auditEvidence').mockResolvedValue(matchedEvidence);
    const user = userEvent.setup();
    render(<AuditTrail events={[localEvent]} />);
    await screen.findByText('Sequence 42 · success');

    await user.click(screen.getByRole('button', { name: 'Refresh audit evidence' }));

    expect(spy).toHaveBeenCalledTimes(2);
    expect(screen.getByText('Policy decision ALLOW with reason POLICY_ALLOW')).toBeInTheDocument();
  });
});
