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

const severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

describe('IncidentSummary', () => {
  it('shows the server-provided retention state without claiming anonymity', () => {
    render(<IncidentSummary incident={incident} />);

    const retention = screen.getByLabelText('Data retention');
    expect(retention).toHaveClass('retention-panel');
    expect(screen.getByText(/Expires automatically on/i)).toBeInTheDocument();
    expect(screen.getByText(/Sensitive values are rejected before local storage/i)).toBeInTheDocument();
    expect(screen.getByText(/it is not anonymous data/i)).toBeInTheDocument();
  });

  it.each(severities)('uses the shared visual patterns for %s severity', (severity) => {
    const { container } = render(<IncidentSummary incident={{ ...incident, severity }} />);

    const badge = screen.getByText(severity, { selector: 'span' });
    expect(badge).toHaveClass('severity-badge', `severity-badge-${severity.toLowerCase()}`);
    expect(container.querySelector('.card-heading > .section-icon')).toBeInTheDocument();
    expect(container.querySelector('.icon-tile')).not.toBeInTheDocument();
    expect(container.querySelector('.severity')).not.toBeInTheDocument();
  });
});
