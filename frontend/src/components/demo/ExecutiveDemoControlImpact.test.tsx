import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { BusinessImpact } from '../../services/privacyGuardApi';
import { DEFAULT_ENTERPRISE_SCENARIO } from '../scenarios/scenarioDefinitions';
import { ExecutiveDemoView } from './ExecutiveDemoView';

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

describe('ExecutiveDemoView control impact', () => {
  it('projects only a compact measured summary and does not invent financial ROI', () => {
    render(
      <ExecutiveDemoView
        scenario={DEFAULT_ENTERPRISE_SCENARIO}
        systemStatus={null}
        statusLoading={false}
        agentAnalysis={null}
        selectedAction={null}
        decision={null}
        remediationExecution={null}
        businessImpact={impact}
        businessImpactLoading={false}
        businessImpactError={null}
        evidence={null}
        evidenceLoading={false}
        evidenceError={null}
        onOpenEvidence={vi.fn()}
      />,
    );

    const summary = screen.getByTestId('control-impact-compact');
    expect(summary).toHaveTextContent('12 blocked');
    expect(summary).toHaveTextContent('8 minimized');
    expect(summary).toHaveTextContent('17 verified');
    expect(summary).toHaveTextContent('420 ms median decision');
    expect(summary).toHaveTextContent(/Financial ROI is not inferred/i);
    expect(summary).not.toHaveTextContent(/money saved|breach avoided/i);
  });
});
