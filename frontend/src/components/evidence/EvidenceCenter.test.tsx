import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { EvidenceCenter } from './EvidenceCenter';

describe('EvidenceCenter', () => {
  it('renders PASS, FAIL and NOT RUN without counting NOT RUN as PASS', () => {
    render(<EvidenceCenter evidence={{
      metadata: { source: 'T3N_TESTNET', generatedAt: '2026-09-12T00:00:00Z', network: 'testnet', sdkVersion: '5.2.0', tenantDid: 'did:t3n:tenant', agentDid: 'did:t3n:agent', contractId: 'z:tenant:privacy-guard', contractVersion: '0.2.0', wasmSha256: 'a'.repeat(64) },
      scenarios: [
        { id: 's-pass', expected: 'DENY', actual: 'DENY', status: 'PASS' },
        { id: 's-not-run', expected: 'blocked', actual: null, status: 'NOT_RUN' },
      ],
      totals: { pass: 1, fail: 0, notRun: 1 },
    }} loading={false} error={null} onRefresh={vi.fn()} />);

    expect(screen.getByText('1 PASS')).toBeInTheDocument();
    expect(screen.getByText('1 NOT RUN')).toBeInTheDocument();
    expect(screen.getByText(/never counted as PASS/i)).toBeInTheDocument();
  });

  it('shows explicit empty live-evidence copy', () => {
    render(<EvidenceCenter evidence={null} loading={false} error={null} onRefresh={vi.fn()} />);
    expect(screen.getByText('No live T3N evidence has been generated yet.')).toBeInTheDocument();
  });
});
