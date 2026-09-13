import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
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
      agentCardVerifiedAt: '2026-09-12T00:00:01Z', agentCardServices: registered ? ['DID'] : [],
      contractId: 'z:tenant:privacy-guard', contractVersion: '0.4.0', wasmSha256: 'a'.repeat(64),
      policyVersion: '2026-09-12.1', policyHash: 'b'.repeat(64),
      trustAnchorVerified: true, trustManifestFloorPersisted: true, trustManifestVersion: 42,
    },
    scenarios: [],
    totals: { pass: 0, fail: 0, notRun: 0 },
  };
}

describe('EvidenceCenter', () => {
  it('renders source revision, proposal agent, executor, policy and trust provenance without overstating authorization or attestation', () => {
    const evidence = evidenceWithRegistrationState('REGISTERED');
    evidence.scenarios = [
      { id: 'LIVE-PROPOSAL-CANNOT-EXECUTE', expected: 'Proposal Agent DID rejected', actual: 'REJECTED', status: 'PASS' },
      { id: 's-not-run', expected: 'blocked', actual: null, status: 'NOT_RUN' },
    ];
    evidence.totals = { pass: 1, fail: 0, notRun: 1 };

    render(<EvidenceCenter evidence={evidence} loading={false} error={null} onRefresh={vi.fn()} />);

    expect(screen.getByText('Observed security outcomes on T3N testnet')).toBeInTheDocument();
    expect(screen.getByText(SOURCE_COMMIT)).toBeInTheDocument();
    expect(screen.getByText('CLEAN')).toBeInTheDocument();
    expect(screen.getByText(/public source revision used to generate this evidence bundle/i)).toBeInTheDocument();
    expect(screen.getByText(/WASM and policy hashes remain the executed artifact identities/i)).toBeInTheDocument();
    expect(screen.getByText('REGISTERED')).toBeInTheDocument();
    expect(screen.getByText('Card check')).toBeInTheDocument();
    expect(screen.queryByText('Card verified')).not.toBeInTheDocument();
    expect(screen.getByText('did:t3n:proposal-agent')).toBeInTheDocument();
    expect(screen.getByText('did:t3n:protected-executor')).toBeInTheDocument();
    expect(screen.getByText('2026-09-12.1')).toBeInTheDocument();
    expect(screen.getByText('b'.repeat(64))).toBeInTheDocument();
    expect(screen.getByText('VERIFIED')).toBeInTheDocument();
    expect(screen.getByText('PERSISTED')).toBeInTheDocument();
    expect(screen.getByText(/separate authenticated T3N principal/i)).toBeInTheDocument();
    expect(screen.getByText(/not a claim of per-request hardware attestation/i)).toBeInTheDocument();
  });

  it.each([
    ['NOT_REGISTERED', 'NOT REGISTERED'],
    ['MISMATCH', 'CARD/DID MISMATCH'],
    ['UNAVAILABLE', 'UNAVAILABLE'],
  ] as const)('does not render %s onboarding state as a successful verification', (state, label) => {
    render(<EvidenceCenter evidence={evidenceWithRegistrationState(state)} loading={false} error={null} onRefresh={vi.fn()} />);

    expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.getByText('Card check')).toBeInTheDocument();
    expect(screen.queryByText('Card verified')).not.toBeInTheDocument();
    expect(screen.getByText('Not resolved')).toBeInTheDocument();
    expect(screen.getByText('Not available')).toBeInTheDocument();
  });

  it('renders dirty source state explicitly without labelling it verified', () => {
    const evidence = evidenceWithRegistrationState('MISMATCH');
    evidence.metadata.sourceTreeClean = false;
    render(<EvidenceCenter evidence={evidence} loading={false} error={null} onRefresh={vi.fn()} />);

    expect(screen.getByText('DIRTY')).toBeInTheDocument();
    expect(screen.getByText(/DIRTY is disclosed explicitly and is not treated as verified source/i)).toBeInTheDocument();
  });

  it('shows the proof meaning before an explicit empty live-evidence state', () => {
    render(<EvidenceCenter evidence={null} loading={false} error={null} onRefresh={vi.fn()} />);
    expect(screen.getByText('What this proves')).toBeInTheDocument();
    expect(screen.getByText('No live T3N evidence has been generated yet.')).toBeInTheDocument();
  });
});
