import '@testing-library/jest-dom/vitest';
import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import type { AgentAnalysis } from '../../services/privacyGuardApi';
import { AgentProposalPanel } from './AgentProposalPanel';

const analysis: AgentAnalysis = {
  provider: 'openai-compatible',
  model: 'tool-model',
  incident: {
    id: 'incident-1', title: 'Private notification', severity: 'HIGH', summary: 'Synthetic incident', source: 'test', status: 'OPEN', createdAt: '2026-09-12T00:00:00Z',
  },
  action: {
    id: 'action-1', incidentId: 'incident-1', requestId: 'request-1', action: 'notify-security', resource: 'incident:42', purpose: 'incident-notification', host: 'postman-echo.com',
    fields: ['incident_id', 'severity', 'summary'], privateRefs: ['verified_email'], status: 'EVALUATED', createdAt: '2026-09-12T00:00:00Z',
  },
  decision: {
    id: 'decision-1', actionProposalId: 'action-1', decision: 'ALLOW', reasonCode: 'POLICY_ALLOW', reason: 'Allowed',
    allowedFields: ['incident_id', 'severity', 'summary'], redactedFields: [], allowedPrivateRefs: ['verified_email'], redactedPrivateRefs: [], evaluatedAt: '2026-09-12T00:00:00Z',
  },
};

describe('AgentProposalPanel', () => {
  it('renders only the logical private-data category and explains the T3N boundary', () => {
    render(<AgentProposalPanel analysis={analysis} />);

    expect(screen.getByText('Verified email')).toBeInTheDocument();
    expect(screen.getByText('Plaintext visible to agent')).toBeInTheDocument();
    expect(screen.getByText('Resolved by T3N at egress')).toBeInTheDocument();
    expect(screen.queryByText(/@example\.com/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/\{\{profile\./i)).not.toBeInTheDocument();
  });
});
