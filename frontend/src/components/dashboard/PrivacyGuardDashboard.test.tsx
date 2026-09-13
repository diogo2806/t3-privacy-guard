import '@testing-library/jest-dom/vitest';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import {
  PrivacyGuardApiError,
  privacyGuardApi,
  type ActionProposal,
  type Incident,
  type PolicyDecision,
  type SystemStatus,
} from '../../services/privacyGuardApi';
import { PrivacyGuardDashboard } from './PrivacyGuardDashboard';

const incident: Incident = {
  id: 'incident-old',
  title: 'Previously loaded credential incident',
  severity: 'HIGH',
  summary: 'Synthetic historical result',
  source: 'test',
  status: 'OPEN',
  createdAt: '2026-09-12T20:00:00Z',
};

const action: ActionProposal = {
  id: 'action-old',
  incidentId: incident.id,
  requestId: 'request-old',
  action: 'revoke-credential',
  resource: 'credential:demo',
  purpose: 'incident-remediation',
  host: 'postman-echo.com',
  fields: ['incident_id', 'credential_id', 'reason'],
  privateRefs: [],
  status: 'EVALUATED',
  createdAt: '2026-09-12T20:00:01Z',
};

const decision: PolicyDecision = {
  id: 'decision-old',
  actionProposalId: action.id,
  decision: 'ALLOW',
  reasonCode: 'POLICY_ALLOW',
  reason: 'Synthetic test decision',
  allowedFields: action.fields,
  redactedFields: [],
  allowedPrivateRefs: [],
  redactedPrivateRefs: [],
  evaluatedAt: '2026-09-12T20:00:02Z',
};

const systemStatus: SystemStatus = {
  gatewayReachable: true,
  tenantAuthenticated: true,
  network: 'testnet',
  tenantDid: 'did:t3n:tenant-test',
  agentConfigured: true,
  agentAuthenticated: true,
  agentDid: 'did:t3n:agent-test',
  contractResolved: true,
  contractId: 'privacy-guard-test',
  contractVersion: 'test',
  delegationState: 'ACTIVE',
  delegatedFunctions: ['evaluate-action'],
  allowedHosts: ['postman-echo.com'],
  message: 'Synthetic status',
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe('PrivacyGuardDashboard enterprise scenarios', () => {
  it('clears the previous result when the operator switches scenarios without calling the agent', async () => {
    const user = userEvent.setup();
    const analyzeSpy = vi.spyOn(privacyGuardApi, 'analyzeAgent');
    vi.spyOn(privacyGuardApi, 'session').mockResolvedValue({ authenticated: true, username: 'operator' });
    vi.spyOn(privacyGuardApi, 'systemStatus').mockResolvedValue(systemStatus);
    vi.spyOn(privacyGuardApi, 'listIncidents').mockResolvedValue([incident]);
    vi.spyOn(privacyGuardApi, 'listActions').mockResolvedValue([action]);
    vi.spyOn(privacyGuardApi, 'history').mockResolvedValue([]);
    vi.spyOn(privacyGuardApi, 'getDecision').mockResolvedValue(decision);
    vi.spyOn(privacyGuardApi, 'getRemediation').mockRejectedValue(new PrivacyGuardApiError('Not found', 404));

    render(<PrivacyGuardDashboard />);

    expect(await screen.findByText('Previously loaded credential incident')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /Account takeover/i }));

    expect(screen.getByText('No scenario result yet')).toBeInTheDocument();
    expect(screen.queryByText('Previously loaded credential incident')).not.toBeInTheDocument();
    expect(screen.getByText(/Previous result was cleared/i)).toBeInTheDocument();
    expect(analyzeSpy).not.toHaveBeenCalled();
    await waitFor(() => expect((screen.getByLabelText('Prompt') as HTMLTextAreaElement).value).toContain('acct-demo-42'));
  });
});
