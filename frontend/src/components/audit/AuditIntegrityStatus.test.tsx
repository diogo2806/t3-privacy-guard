import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { AuditIntegrity, AuditIntegrityState } from '../../services/privacyGuardApi';
import { AuditIntegrityStatus } from './AuditIntegrityStatus';

function integrity(state: AuditIntegrityState): AuditIntegrity {
  return {
    state,
    eventsChecked: state === 'VERIFIED' ? 3 : 0,
    head: state === 'VERIFIED' ? 'a'.repeat(64) : null,
    version: state === 'LEGACY_UNVERIFIED' ? 'legacy' : 'v1',
    detail: `Synthetic ${state} detail`,
  };
}

describe('AuditIntegrityStatus', () => {
  it.each([
    ['VERIFIED', 'Integrity verified', 'status'],
    ['BROKEN', 'Integrity broken', 'alert'],
    ['KEY_MISMATCH', 'Integrity key unavailable', 'alert'],
    ['LEGACY_UNVERIFIED', 'Legacy history unverified', 'status'],
    ['PURGED', 'Not available after retention purge', 'status'],
    ['NOT_AVAILABLE', 'Integrity not available', 'status'],
  ] as const)('renders %s with honest copy and semantics', (state, label, role) => {
    render(<AuditIntegrityStatus integrity={integrity(state)} />);

    expect(screen.getByLabelText(`Local audit integrity: ${label}`)).toHaveAttribute('role', role);
    expect(screen.getByText(label)).toBeInTheDocument();
  });

  it('never describes legacy or purged history as verified', () => {
    const { rerender } = render(<AuditIntegrityStatus integrity={integrity('LEGACY_UNVERIFIED')} />);
    expect(screen.getByText(/predate local HMAC protection/i)).toBeInTheDocument();
    expect(screen.queryByText('Integrity verified')).not.toBeInTheDocument();

    rerender(<AuditIntegrityStatus integrity={integrity('PURGED')} />);
    expect(screen.getByText(/removed by the retention policy/i)).toBeInTheDocument();
    expect(screen.queryByText('Integrity verified')).not.toBeInTheDocument();
  });
});
