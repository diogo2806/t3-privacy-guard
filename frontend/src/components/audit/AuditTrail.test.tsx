import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { AuditTrail } from './AuditTrail';
import type { AuditHistory } from '../../services/privacyGuardApi';

function history(state: AuditHistory['integrity']['state']): AuditHistory {
  return {
    integrity: {
      state,
      eventsChecked: state === 'VERIFIED' ? 1 : 0,
      head: state === 'VERIFIED' ? 'a'.repeat(64) : null,
      version: 'v1',
      detail: 'Server verification detail.',
    },
    events: [{
      id: 'event-1',
      incidentId: 'incident-1',
      type: 'POLICY_DECISION',
      message: 'Policy decision DENY with reason HOST_NOT_ALLOWED',
      createdAt: '2026-09-12T20:00:00Z',
      sequence: 1,
    }],
  };
}

describe('AuditTrail', () => {
  it('shows verified local integrity separately from event content', () => {
    render(<AuditTrail history={history('VERIFIED')} />);

    expect(screen.getByText('Integrity verified')).toBeInTheDocument();
    expect(screen.getByText('Checked events: 1 · Integrity version: v1')).toBeInTheDocument();
    expect(screen.getByText('Policy decision DENY with reason HOST_NOT_ALLOWED')).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('tamper-proof');
    expect(document.body.textContent).not.toContain('immutable');
  });

  it('warns the operator not to rely on a broken trail as proof', () => {
    render(<AuditTrail history={history('BROKEN')} />);

    expect(screen.getByRole('alert')).toHaveTextContent('Integrity broken');
    expect(screen.getByRole('alert')).toHaveTextContent('Do not use this local trail as proof until investigated.');
  });

  it('does not present legacy or purged history as verified', () => {
    const { rerender } = render(<AuditTrail history={history('LEGACY_UNVERIFIED')} />);
    expect(screen.getByText('Legacy history unverified')).toBeInTheDocument();
    expect(screen.queryByText('Integrity verified')).not.toBeInTheDocument();

    rerender(<AuditTrail history={{ ...history('PURGED'), events: [] }} />);
    expect(screen.getByText('Not available after retention purge')).toBeInTheDocument();
    expect(screen.getByText('No retained audit events are available.')).toBeInTheDocument();
  });
});
