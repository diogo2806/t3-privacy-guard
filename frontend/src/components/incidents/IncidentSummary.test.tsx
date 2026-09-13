import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { IncidentSummary } from './IncidentSummary';

const incident = {
  id: 'incident-1',
  title: 'Synthetic incident',
  severity: 'HIGH' as const,
  summary: 'Only minimized operational text is shown.',
  source: 'test-source',
  status: 'OPEN',
  createdAt: '2026-09-12T12:00:00Z',
  expiresAt: '2026-09-19T12:00:00Z',
  retentionState: 'ACTIVE' as const,
};

describe('IncidentSummary', () => {
  it('shows the server-provided retention state without claiming anonymity', () => {
    render(<IncidentSummary incident={incident} />);

    expect(screen.getByLabelText('Data retention')).toBeInTheDocument();
    expect(screen.getByText(/This incident data expires automatically on/i)).toBeInTheDocument();
    expect(screen.getByText(/High-confidence sensitive literals are rejected before local storage/i)).toBeInTheDocument();
    expect(screen.getByText(/it is not treated as anonymous data/i)).toBeInTheDocument();
  });
});
