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

describe('privacyGuardApi same-origin transport', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('keeps browser API calls relative so they reach the backend that serves the dashboard', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({ authenticated: false }));
    vi.stubGlobal('fetch', fetchMock);

    await privacyGuardApi.session();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/auth/session');
    expect(String(fetchMock.mock.calls[0]?.[0])).not.toContain('api-privacy.iforce.com.br');
    const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(request.credentials).toBe('same-origin');
  });
});

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

describe('privacyGuardApi.businessImpact', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('reads the selected aggregate window without sending mutation data', async () => {
    const impact = {
      window: '24H', from: '2026-09-13T12:00:00Z', to: '2026-09-14T12:00:00Z', retentionLimited: false,
      evaluatedActions: 4, deniedBeforeEgress: 1, minimizedDecisions: 1, redactedNormalFieldNames: 2, redactedPrivateRefs: 0,
      humanAuthorizedRemediations: 2, verifiedCompleted: 1, unverified: 1, failed: 0, finalizedExecutions: 2,
      blockedRatePct: 25, verifiedCompletionRatePct: 50, medianDecisionMs: 420, medianVerifiedOutcomeMs: 3100,
    };
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse(impact));
    vi.stubGlobal('fetch', fetchMock);

    const result = await privacyGuardApi.businessImpact('24h');

    expect(result).toEqual(impact);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/business-impact?window=24h');
    const request = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(request.method).toBe('GET');
    expect(request.body).toBeUndefined();
  });
});

describe('privacyGuardApi legacy wire values', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('presents the legacy control-plane diagnostic as an unavailable trust runtime', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(jsonResponse({ network: 'selfhosted', enterpriseIntegrationState: 'UNKNOWN', enterpriseIntegrationDiagnosticCode: 'T3N_CONTROL_PLANE_UNAVAILABLE' }))
      .mockResolvedValueOnce(jsonResponse({ network: 'selfhosted', enterpriseIntegrationState: 'UNKNOWN', enterpriseIntegrationDiagnosticCode: 'POLICY_UNAVAILABLE' }))
      .mockResolvedValueOnce(jsonResponse({ network: 'selfhosted', enterpriseIntegrationState: 'UNKNOWN' }));
    vi.stubGlobal('fetch', fetchMock);

    expect((await privacyGuardApi.systemStatus()).enterpriseIntegrationDiagnosticCode).toBe('TRUST_RUNTIME_UNAVAILABLE');
    expect((await privacyGuardApi.systemStatus()).enterpriseIntegrationDiagnosticCode).toBe('POLICY_UNAVAILABLE');
    expect(await privacyGuardApi.systemStatus()).not.toHaveProperty('enterpriseIntegrationDiagnosticCode');
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/system/status');
  });

  it('maps legacy audit provenance names and the runtime-only status to runtime-neutral fields', async () => {
    const runtimeEvent = {
      sequence: 7, hash: 'hash-7', timestamp: '2026-10-28T12:00:01Z', callerType: 'agent', actorDid: 'agent:proposal',
      onBehalfOfDid: 'tenant:acme', contractId: 'privacy-guard', function: 'evaluate-action', outcome: 'success',
    };
    const fetchMock = vi.fn().mockResolvedValueOnce(jsonResponse({
      localEvents: [{ id: 'local-1', incidentId: 'incident/1', type: 'POLICY_DECISION', message: 'Policy decision', createdAt: '2026-10-28T12:00:00Z', status: 'LOCAL_ONLY', t3nSequence: null, t3nFunction: 'evaluate-action', matchedSequence: null }],
      t3nEvents: [{ ...runtimeEvent, status: 'T3N_ONLY' }],
      provenance: { localAvailable: true, t3nAvailable: true, t3nComplete: false, matched: 0, unmatched: 0, localOnly: 1, t3nOnly: 1, message: 'guard-runtime activity is available.' },
      integrity: { state: 'VERIFIED', eventsChecked: 1, head: null, version: 'v1', detail: 'HMAC chain verified.' },
      nextSequence: 6,
      limit: 25,
    }));
    vi.stubGlobal('fetch', fetchMock);

    const evidence = await privacyGuardApi.auditEvidence('incident/1', 25);

    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/incidents/incident%2F1/audit-evidence?limit=25');
    expect(evidence.localEvents).toEqual([{ id: 'local-1', incidentId: 'incident/1', type: 'POLICY_DECISION', message: 'Policy decision', createdAt: '2026-10-28T12:00:00Z', status: 'LOCAL_ONLY', runtimeSequence: null, runtimeFunction: 'evaluate-action', matchedSequence: null }]);
    expect(evidence.runtimeEvents).toEqual([{ ...runtimeEvent, status: 'RUNTIME_ONLY' }]);
    expect(evidence.provenance).toEqual({ localAvailable: true, runtimeAvailable: true, runtimeComplete: false, matched: 0, unmatched: 0, localOnly: 1, runtimeOnly: 1, message: 'guard-runtime activity is available.' });
    expect(evidence.integrity.state).toBe('VERIFIED');
    expect(evidence.nextSequence).toBe(6);
    expect(evidence.limit).toBe(25);
    expect(Object.keys(evidence).sort()).toEqual(['integrity', 'limit', 'localEvents', 'nextSequence', 'provenance', 'runtimeEvents']);
  });
});
