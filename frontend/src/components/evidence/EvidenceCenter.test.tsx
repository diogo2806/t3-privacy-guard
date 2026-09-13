import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { EvidenceCenter } from './EvidenceCenter';

describe('EvidenceCenter', () => {
  it('renders trust provenance and Agent Card evidence without overstating either attestation or authorization', () => {
    render(<EvidenceCenter evidence={{
      metadata: {
        source: 'T3N_TESTNET', generatedAt: '2026-09-12T00:00:00Z', network: 'testnet', sdkVersion: '5.2.0',
        tenantDid: 'did:t3n:tenant', agentDid: 'did:t3n:agent',
        agentRegistrationState: 'REGISTERED', agentCardUri: 'https://node.example/api/agent-card/did:t3n:agent', agentCardSha256: 'c'.repeat(64),
        agentCardVerifiedAt: '2026-09-12T00:00:01Z', agentCardServices: ['DID'],
        contractId: 'z:tenant:privacy-guard', contractVersion: '0.3.0', wasmSha256: 'a'.repeat(64),
        trustAnchorVerified: true, trustManifestFloorPersisted: true, trustManifestVersion: 42,
      },
      scenarios: [
        { id: 's-pass', expected: 'DENY', actual: 'DENY', status: 'PASS' },
        { id: 's-not-run', expected: 'blocked', actual: null, status: 'NOT_RUN' },
      ],
      totals: { pass: 1, fail: 0, notRun: 1 },
    }} loading={false} error={null} onRefresh={vi.fn()} />);

    expect(screen.getByText('What this proves')).toBeInTheDocument();
    expect(screen.getByText('REGISTERED')).toHaveClass('status-pill-ok');
    expect(screen.getByText('DID')).toBeInTheDocument();
    expect(screen.getByText('VERIFIED')).toBeInTheDocument();
    expect(screen.getByText('PERSISTED')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText('1 PASS')).toBeInTheDocument();
    expect(screen.getByText('1 NOT RUN')).toBeInTheDocument();
    expect(screen.getByText(/not a claim of per-request hardware attestation/i)).toBeInTheDocument();
    expect(screen.getByText(/does not grant contract access/i)).toBeInTheDocument();
    expect(screen.getByText(/never counted as PASS/i)).toBeInTheDocument();
  });

  it('renders card mismatch as a non-success evidence state', () => {
    render(<EvidenceCenter evidence={{
      metadata: {
        source: 'T3N_TESTNET', generatedAt: '2026-09-12T00:00:00Z', network: 'testnet', sdkVersion: '5.2.0', tenantDid: 'did:t3n:tenant', agentDid: 'did:t3n:agent',
        agentRegistrationState: 'MISMATCH', agentCardUri: 'https://node.example/card', agentCardSha256: 'c'.repeat(64), agentCardVerifiedAt: '2026-09-12T00:00:01Z', agentCardServices: [],
        contractId: 'z:tenant:privacy-guard', contractVersion: '0.3.0', wasmSha256: 'a'.repeat(64), trustAnchorVerified: true, trustManifestFloorPersisted: true, trustManifestVersion: 42,
      },
      scenarios: [], totals: { pass: 0, fail: 0, notRun: 0 },
    }} loading={false} error={null} onRefresh={vi.fn()} />);
    expect(screen.getByText('CARD/DID MISMATCH')).toHaveClass('status-pill-off');
  });

  it('shows the proof meaning before an explicit empty live-evidence state', () => {
    render(<EvidenceCenter evidence={null} loading={false} error={null} onRefresh={vi.fn()} />);
    expect(screen.getByText('What this proves')).toBeInTheDocument();
    expect(screen.getByText('No live T3N evidence has been generated yet.')).toBeInTheDocument();
  });
});
