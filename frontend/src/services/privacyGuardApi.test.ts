import { afterEach, describe, expect, it, vi } from 'vitest';
import { privacyGuardApi } from './privacyGuardApi';

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(),
    json: async () => body,
  } as Response;
}

describe('privacyGuardApi.analyzeAgentInIncident', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('posts only the prompt to the existing-incident agent proposal endpoint', async () => {
    const analysis = {
      provider: 'openai-compatible', model: 'tool-model',
      incident: { id: 'incident/42', title: 'Incident', severity: 'CRITICAL', summary: 'Synthetic', source: 'test', status: 'OPEN', createdAt: '2026-09-13T00:00:00Z', expiresAt: '2026-09-20T00:00:00Z', retentionState: 'ACTIVE' },
      action: { id: 'action-2', incidentId: 'incident/42', requestId: 'ai-2', action: 'revoke-credential', resource: 'credential:production-security-api', purpose: 'incident-remediation', host: 'postman-echo.com', fields: ['incident_id', 'credential_id', 'reason'], privateRefs: [], status: 'EVALUATED', createdAt: '2026-09-13T00:00:00Z' },
      decision: { id: 'decision-2', actionProposalId: 'action-2', decision: 'ALLOW', reasonCode: 'POLICY_ALLOW', reason: 'Allowed', allowedFields: ['incident_id', 'credential_id', 'reason'], redactedFields: [], allowedPrivateRefs: [], redactedPrivateRefs: [], evaluatedAt: '2026-09-13T00:00:00Z' },
    };
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ token: 'csrf-token', headerName: 'X-CSRF-TOKEN' }))
      .mockResolvedValueOnce(jsonResponse(analysis));
    vi.stubGlobal('fetch', fetchMock);

    const result = await privacyGuardApi.analyzeAgentInIncident('incident/42', 'minimum remediation prompt');

    expect(result).toEqual(analysis);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[1]?.[0]).toBe('/api/incidents/incident%2F42/agent-proposals');
    const request = fetchMock.mock.calls[1]?.[1] as RequestInit;
    expect(request.method).toBe('POST');
    expect(JSON.parse(String(request.body))).toEqual({ prompt: 'minimum remediation prompt' });
    expect(JSON.parse(String(request.body))).not.toHaveProperty('action');
    expect(JSON.parse(String(request.body))).not.toHaveProperty('decision');
  });
});
