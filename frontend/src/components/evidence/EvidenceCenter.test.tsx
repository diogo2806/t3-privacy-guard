import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { EvidenceCenter } from './EvidenceCenter';

describe('EvidenceCenter', () => {
  it('explains proof semantics and renders policy/trust provenance without overstating attestation', () => {
    render(<EvidenceCenter evidence={{
      metadata: {
        source: 'T3N_TESTNET', generatedAt: '2026-09-12T00:00:00Z', network: 'testnet', sdkVersion: '5.2.0',
        tenantDid: 'did:t3n:tenant', agentDid: 'did:t3n:agent', contractId: 'z:tenant:privacy-guard',
        contractVersion: '0.4.0', wasmSha256: 'a'.repeat(64), policyVersion: '2026-09-12.1', policyHash: 'b'.repeat(64),
        trustAnchorVerified: true, trustManifestFloorPersisted: true, trustManifestVersion: 42,
      },
      scenarios: [
        { id: 's-pass', expected: 'DENY', actual: 'DENY', status: 'PASS' },
        { id: 's-not-run', expected: 'blocked', actual: null, status: 'NOT_RUN' },
      ],
      totals: { pass: 1, fail: 0, notRun: 1 },
    }} loading={false} error={null} onRefresh={vi.fn()} />);

    expect(screen.getByText('What this proves')).toBeInTheDocument();
    expect(screen.getByText('Observed security outcomes on T3N testnet')).toBeInTheDocument();
    expect(screen.getByText('1 PASS')).toBeInTheDocument();
    expect(screen.getByText('1 NOT RUN')).toBeInTheDocument();
    expect(screen.getByText('0.4.0')).toBeInTheDocument();
    expect(screen.getByText('2026-09-12.1')).toBeInTheDocument();
    expect(screen.getByText('b'.repeat(64))).toBeInTheDocument();
    expect(screen.getByText('VERIFIED')).toBeInTheDocument();
    expect(screen.getByText('PERSISTED')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
    expect(screen.getByText(/not a claim of per-request hardware attestation/i)).toBeInTheDocument();
    expect(screen.getByText(/never counted as PASS/i)).toBeInTheDocument();
  });

  it('shows the proof meaning before an explicit empty live-evidence state', () => {
    render(<EvidenceCenter evidence={null} loading={false} error={null} onRefresh={vi.fn()} />);
    expect(screen.getByText('What this proves')).toBeInTheDocument();
    expect(screen.getByText('No live T3N evidence has been generated yet.')).toBeInTheDocument();
  });
});
