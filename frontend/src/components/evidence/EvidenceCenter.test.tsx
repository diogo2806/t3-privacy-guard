import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { EvidenceCenter } from './EvidenceCenter';

describe('EvidenceCenter', () => {
  it('renders Agent Card, policy and trust provenance without overstating authorization or attestation', () => {
    render(<EvidenceCenter evidence={{
      metadata: {
        source: 'T3N_TESTNET', generatedAt: '2026-09-12T00:00:00Z', network: 'testnet', sdkVersion: '5.2.0',
        tenantDid: 'did:t3n:tenant', agentDid: 'did:t3n:agent',
        agentRegistrationState: 'REGISTERED', agentCardUri: 'https://node.example/card', agentCardSha256: 'c'.repeat(64),
        agentCardVerifiedAt: '2026-09-12T00:00:01Z', agentCardServices: ['DID'],
        contractId: 'z:tenant:privacy-guard', contractVersion: '0.4.0', wasmSha256: 'a'.repeat(64),
        policyVersion: '2026-09-12.1', policyHash: 'b'.repeat(64),
        trustAnchorVerified: true, trustManifestFloorPersisted: true, trustManifestVersion: 42,
      },
      scenarios: [
        { id: 's-pass', expected: 'DENY', actual: 'DENY', status: 'PASS' },
        { id: 's-not-run', expected: 'blocked', actual: null, status: 'NOT_RUN' },
      ],
      totals: { pass: 1, fail: 0, notRun: 1 },
    }} loading={false} error={null} onRefresh={vi.fn()} />);

    expect(screen.getByText('Observed security outcomes on T3N testnet')).toBeInTheDocument();
    expect(screen.getByText('REGISTERED')).toBeInTheDocument();
    expect(screen.getByText('https://node.example/card')).toBeInTheDocument();
    expect(screen.getByText('c'.repeat(64))).toBeInTheDocument();
    expect(screen.getByText('DID')).toBeInTheDocument();
    expect(screen.getByText('2026-09-12.1')).toBeInTheDocument();
    expect(screen.getByText('b'.repeat(64))).toBeInTheDocument();
    expect(screen.getByText('VERIFIED')).toBeInTheDocument();
    expect(screen.getByText('PERSISTED')).toBeInTheDocument();
    expect(screen.getByText(/discoverability evidence only/i)).toBeInTheDocument();
    expect(screen.getByText(/not a claim of per-request hardware attestation/i)).toBeInTheDocument();
  });

  it('does not render negative onboarding state as success', () => {
    render(<EvidenceCenter evidence={{
      metadata: {
        source: 'T3N_TESTNET', generatedAt: '2026-09-12T00:00:00Z', network: 'testnet', sdkVersion: '5.2.0',
        tenantDid: 'did:t3n:tenant', agentDid: 'did:t3n:agent', agentRegistrationState: 'MISMATCH',
        agentCardUri: null, agentCardSha256: null, agentCardVerifiedAt: '2026-09-12T00:00:01Z', agentCardServices: [],
        contractId: 'z:tenant:privacy-guard', contractVersion: '0.4.0', wasmSha256: 'a'.repeat(64),
        policyVersion: '2026-09-12.1', policyHash: 'b'.repeat(64), trustAnchorVerified: true,
        trustManifestFloorPersisted: true, trustManifestVersion: 42,
      }, scenarios: [], totals: { pass: 0, fail: 0, notRun: 0 },
    }} loading={false} error={null} onRefresh={vi.fn()} />);
    expect(screen.getByText('CARD/DID MISMATCH')).toBeInTheDocument();
  });

  it('shows the proof meaning before an explicit empty live-evidence state', () => {
    render(<EvidenceCenter evidence={null} loading={false} error={null} onRefresh={vi.fn()} />);
    expect(screen.getByText('What this proves')).toBeInTheDocument();
    expect(screen.getByText('No live T3N evidence has been generated yet.')).toBeInTheDocument();
  });
});
