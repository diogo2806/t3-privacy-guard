import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { AgentRegistrationState, EvidenceBundle } from '../../services/privacyGuardApi';
import { EvidenceCenter } from './EvidenceCenter';

const SOURCE_COMMIT = '1'.repeat(40);

function evidenceWithRegistrationState(agentRegistrationState: AgentRegistrationState): EvidenceBundle {
  const registered = agentRegistrationState === 'REGISTERED';
  return {
    metadata: {
      source: 'T3N_TESTNET', generatedAt: '2026-09-12T00:00:00Z', sourceCommitSha: SOURCE_COMMIT, sourceTreeClean: true,
      network: 'testnet', sdkVersion: '5.2.0', tenantDid: 'did:t3n:tenant', agentDid: 'did:t3n:proposal-agent', executorDid: 'did:t3n:protected-executor',
      agentRegistrationState,
      agentCardUri: registered ? 'https://node.example/card' : null,
      agentCardSha256: registered ? 'c'.repeat(64) : null,
      agentCardVerifiedAt: '2026-09-12T00:00:01Z', agentCardServices: registered ? ['A2A', 'DID'] : [],
      contractId: 'z:tenant:privacy-guard', contractVersion: '0.4.0', wasmSha256: 'a'.repeat(64),
      policyVersion: '2026-09-12.1', policyHash: 'b'.repeat(64),
      trustAnchorVerified: true, trustManifestFloorPersisted: true, trustManifestVersion: 42,
    },
    scenarios: [],
    totals: { pass: 0, fail: 0, notRun: 0 },
  };
}

describe('EvidenceCenter', () => {
  it('shows totals and observed outcomes before technical provenance without counting NOT RUN as PASS', () => {
    const evidence = evidenceWithRegistrationState('REGISTERED');
    evidence.scenarios = [
      { id: 'LIVE-PROPOSAL-CANNOT-EXECUTE', expected: 'Proposal Agent DID rejected', actual: 'REJECTED', status: 'PASS' },
      { id: 's-not-run', expected: 'blocked', actual: null, status: 'NOT_RUN' },
    ];
    evidence.totals = { pass: 1, fail: 0, notRun: 1 };

    render(<EvidenceCenter evidence={evidence} loading={false} error={null} onRefresh={vi.fn()} />);

    const summary = screen.getByLabelText('Evidence totals');
    expect(summary).toHaveTextContent('1PASS');
    expect(summary).toHaveTextContent('0FAIL');
    expect(summary).toHaveTextContent('1NOT RUN');
    expect(screen.getByText('Proposal agent blocked from protected execution')).toBeInTheDocument();
    expect(screen.getByText('LIVE-PROPOSAL-CANNOT-EXECUTE')).toBeInTheDocument();
    expect(screen.getByText(/NOT RUN is not proof/i)).toBeInTheDocument();
  });

  it('keeps source, identity, discoverability, contract and trust provenance available through accessible details', async () => {
    const user = userEvent.setup();
    const evidence = evidenceWithRegistrationState('REGISTERED');
    render(<EvidenceCenter evidence={evidence} loading={false} error={null} onRefresh={vi.fn()} />);

    await user.click(screen.getByText('Source & build'));
    await user.click(screen.getByText('Trust & network'));
    await user.click(screen.getByText('Identities & discoverability'));
    await user.click(screen.getByText('Contract & policy'));

    expect(screen.getByText(SOURCE_COMMIT)).toBeVisible();
    expect(screen.getByText('did:t3n:proposal-agent')).toBeVisible();
    expect(screen.getByText('did:t3n:protected-executor')).toBeVisible();
    expect(screen.getByText('REGISTERED')).toBeVisible();
    expect(screen.getByText('OBSERVED')).toHaveClass('status-pill-ok');
    expect(screen.getByText('b'.repeat(64))).toBeVisible();
    expect(screen.getAllByText('VERIFIED').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('PERSISTED')).toBeVisible();
    expect(screen.getByText(/not per-request hardware attestation/i)).toBeVisible();
    expect(screen.getByText(/do not grant delegated authority/i)).toBeVisible();
    expect(screen.getByText(/not that public reachability was proved/i)).toBeVisible();
  });

  it.each([
    ['NOT_REGISTERED', 'NOT REGISTERED'],
    ['MISMATCH', 'CARD/DID MISMATCH'],
    ['UNAVAILABLE', 'UNAVAILABLE'],
  ] as const)('does not render %s onboarding state or absent A2A observation as successful verification', async (state, label) => {
    const user = userEvent.setup();
    render(<EvidenceCenter evidence={evidenceWithRegistrationState(state)} loading={false} error={null} onRefresh={vi.fn()} />);
    await user.click(screen.getByText('Identities & discoverability'));

    expect(screen.getByText(label)).toBeVisible();
    expect(screen.getByText('NOT OBSERVED')).toHaveClass('status-pill-off');
    expect(screen.getByText('Not resolved')).toBeVisible();
    expect(screen.getByText('Not available')).toBeVisible();
  });

  it('renders dirty source state explicitly and explains that CLEAN/DIRTY is not an audit claim', async () => {
    const user = userEvent.setup();
    const evidence = evidenceWithRegistrationState('MISMATCH');
    evidence.metadata.sourceTreeClean = false;
    render(<EvidenceCenter evidence={evidence} loading={false} error={null} onRefresh={vi.fn()} />);
    await user.click(screen.getByText('Source & build'));

    expect(screen.getAllByText('DIRTY').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/not an independent source audit/i)).toBeVisible();
  });

  it('shows the proof meaning before an explicit empty live-evidence state', () => {
    render(<EvidenceCenter evidence={null} loading={false} error={null} onRefresh={vi.fn()} />);
    expect(screen.getByText('What this proves')).toBeInTheDocument();
    expect(screen.getByText('No live T3N evidence has been generated yet.')).toBeInTheDocument();
  });
});
