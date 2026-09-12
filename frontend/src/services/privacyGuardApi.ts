export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DecisionType = 'ALLOW' | 'REDACT' | 'DENY';
export type ProposalStatus = 'PENDING' | 'EVALUATED' | 'REMEDIATION_AUTHORIZED' | 'REMEDIATED';

export interface Incident { id: string; title: string; severity: Severity; summary: string; source: string; status: string; createdAt: string; }
export interface ActionProposal { id: string; incidentId: string; requestId: string; action: string; resource: string; purpose: string; host?: string | null; fields: string[]; status: ProposalStatus; createdAt: string; }
export interface PolicyDecision { id: string; actionProposalId: string; decision: DecisionType; reasonCode: string; reason: string; allowedFields: string[]; redactedFields: string[]; evaluatedAt: string; }
export interface AuditEvent { id: string; incidentId: string; type: string; message: string; createdAt: string; }
export interface SystemStatus {
  gatewayReachable: boolean;
  t3nReady: boolean;
  network?: string | null;
  tenantDid?: string | null;
  agentConfigured: boolean;
  agentReady: boolean;
  agentDid?: string | null;
  contractRegistered: boolean;
  contractId?: string | null;
  contractVersion?: string | null;
  contractFunctions: string[];
  message: string;
}

export class PrivacyGuardApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'PrivacyGuardApiError';
  }
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  });
  if (!response.ok) {
    let message = `Request failed with status ${response.status}.`;
    try {
      const problem = await response.json() as { detail?: string; title?: string };
      message = problem.detail || problem.title || message;
    } catch {
      // Keep the sanitized generic status message when no JSON problem body exists.
    }
    throw new PrivacyGuardApiError(message, response.status);
  }
  return response.json() as Promise<T>;
}

export const privacyGuardApi = {
  systemStatus: () => api<SystemStatus>('/api/system/status'),
  listIncidents: () => api<Incident[]>('/api/incidents'),
  getIncident: (id: string) => api<Incident>(`/api/incidents/${encodeURIComponent(id)}`),
  createIncident: (input: { title: string; severity: Severity; summary: string; source: string }) => api<Incident>('/api/incidents', { method: 'POST', body: JSON.stringify(input) }),
  listActions: (incidentId: string) => api<ActionProposal[]>(`/api/incidents/${encodeURIComponent(incidentId)}/actions`),
  createAction: (incidentId: string, input: { requestId: string; action: string; resource: string; purpose: string; host?: string; fields: string[] }) => api<ActionProposal>(`/api/incidents/${encodeURIComponent(incidentId)}/actions`, { method: 'POST', body: JSON.stringify(input) }),
  evaluate: (incidentId: string, actionId: string) => api<PolicyDecision>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/evaluate`, { method: 'POST' }),
  getDecision: (incidentId: string, actionId: string) => api<PolicyDecision>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/decision`),
  authorizeRemediation: (incidentId: string, actionId: string) => api<{ incidentId: string; actionId: string; requestId: string; state: ProposalStatus }>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/authorize-remediation`, { method: 'POST' }),
  executeRemediation: (incidentId: string, actionId: string) => api<{ incidentId: string; actionId: string; requestId: string; state: ProposalStatus; httpCode: number; operationId?: string | null }>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/execute-remediation`, { method: 'POST' }),
  history: (incidentId: string) => api<AuditEvent[]>(`/api/incidents/${encodeURIComponent(incidentId)}/history`),
};
