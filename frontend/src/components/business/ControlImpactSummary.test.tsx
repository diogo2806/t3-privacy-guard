import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import type { BusinessImpact } from '../../services/privacyGuardApi';
import { ControlImpactSummary } from './ControlImpactSummary';

const impact: BusinessImpact = {
  window: 'RETAINED',
  from: '2026-09-07T12:00:00Z',
  to: '2026-09-14T12:00:00Z',
  retentionLimited: false,
  evaluatedActions: 40,
  deniedBeforeEgress: 12,
  minimizedDecisions: 8,
  redactedNormalFieldNames: 21,
  redactedPrivateRefs: 4,
  humanAuthorizedRemediations: 19,
  verifiedCompleted: 17,
  unverified: 2,
  failed: 1,
  finalizedExecutions: 20,
  blockedRatePct: 30,
  verifiedCompletionRatePct: 85,
  medianDecisionMs: 420,
  medianVerifiedOutcomeMs: 3100,
};

describe('ControlImpactSummary', () => {
  it('renders only observed control metrics and explicit denominators', () => {
    render(<ControlImpactSummary impact={impact} loading={false} error={null} window="retained" />);

    expect(screen.getByText('40')).toBeInTheDocument();
    expect(screen.getByText('12')).toBeInTheDocument();
    expect(screen.getByText('8')).toBeInTheDocument();
    expect(screen.getByText('17')).toBeInTheDocument();
    expect(screen.getByText(/30\.0% \(12 of 40 evaluated\)/)).toBeInTheDocument();
    expect(screen.getByText(/85\.0% \(17 of 20 finalized\)/)).toBeInTheDocument();
    expect(screen.getByText('420 ms')).toBeInTheDocument();
    expect(screen.getByText('3.1 s')).toBeInTheDocument();
    expect(screen.getByText(/Financial ROI.*NOT MEASURED/i)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/money saved|breach avoided|risk reduced by/i);
  });

  it('keeps absent denominators as NOT OBSERVED instead of inventing zero percent', () => {
    render(<ControlImpactSummary impact={{ ...impact, evaluatedActions: 0, deniedBeforeEgress: 0, finalizedExecutions: 0, verifiedCompleted: 0, blockedRatePct: null, verifiedCompletionRatePct: null, medianDecisionMs: null, medianVerifiedOutcomeMs: null }} loading={false} error={null} window="retained" />);

    expect(screen.getAllByText('NOT OBSERVED').length).toBeGreaterThanOrEqual(4);
    expect(screen.queryByText('0.0%')).not.toBeInTheDocument();
  });

  it('changes observation window through the reusable control', async () => {
    const user = userEvent.setup();
    const onWindowChange = vi.fn();
    render(<ControlImpactSummary impact={impact} loading={false} error={null} window="retained" onWindowChange={onWindowChange} />);

    await user.click(screen.getByRole('button', { name: '24 hours' }));
    expect(onWindowChange).toHaveBeenCalledWith('24h');
    expect(screen.getByRole('button', { name: 'Retained' })).toHaveAttribute('aria-pressed', 'true');
  });

  it('provides a compact executive projection without adding financial claims', () => {
    render(<ControlImpactSummary impact={impact} loading={false} error={null} window="retained" compact />);

    const compact = screen.getByTestId('control-impact-compact');
    expect(compact).toHaveTextContent('12 blocked');
    expect(compact).toHaveTextContent('8 minimized');
    expect(compact).toHaveTextContent('17 verified');
    expect(compact).toHaveTextContent('420 ms median decision');
    expect(compact).toHaveTextContent(/Financial ROI is not inferred/i);
    expect(screen.queryByRole('button', { name: '24 hours' })).not.toBeInTheDocument();
  });
});
