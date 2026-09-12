export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DecisionType = 'ALLOW' | 'REDACT' | 'DENY';
export type ProposalStatus = 'PENDING' | 'EVALUATED' | 'REMEDIATION_AUTHORIZED' | 'REMEDIATED';

export interface Incident { id: string; title: string; severity: Severity; summary: string; source: string; status: string; createdAt: string; }
export interface ActionProposal { id: string; incidentId: string; requestId: string; action: string; resource: string; purpose: string; host?: string | null; fields: string[]; status: ProposalStatus; createdAt: string; }
export interface PolicyDecision { id: string; actionProposalId: string; decision: DecisionType; reasonCode: string; reason: string; allowedFields: string[]; redactedFields: string[]; evaluatedAt: string; }
export interface AuditEvent { id: string; incidentId: string; type: string; message: string; createdAt: string; }
export interface OperatorSession { authenticated: boolean; username?: string | null; }
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

interface CsrfState { token: string; headerName: string; }
let csrfState: CsrfState | null = null;

export class PrivacyGuardApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'PrivacyGuardApiError';
  }
}

async function readProblem(response: Response): Promise<string> {
  let message = `Request failed with status ${response.status}.`;
  try {
    const problem = await response.json() as { detail?: string; title?: string };
    message = problem.detail || problem.title || message;
  } catch {
    // Keep the sanitized generic status message when no JSON problem body exists.
  }
  return message;
}

async function ensureCsrf(): Promise<CsrfState> {
  if (csrfState) return csrfState;
  const response = await fetch('/api/auth/csrf', { credentials: 'same-origin' });
  if (!response.ok) throw new PrivacyGuardApiError(await readProblem(response), response.status);
  csrfState = await response.json() as CsrfState;
  return csrfState;
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const headers = new Headers(init?.headers);
  if (init?.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');

  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = await ensureCsrf();
    headers.set(csrf.headerName, csrf.token);
  }

  const response = await fetch(path, {
    ...init,
    method,
    headers,
    credentials: 'same-origin',
  });

  if (!response.ok) {
    if (response.status === 401 || response.status === 403) csrfState = null;
    throw new PrivacyGuardApiError(await readProblem(response), response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const privacyGuardApi = {
  session: () => api<OperatorSession>('/api/auth/session'),
  login: async (input: { username: string; password: string }) => {
    const session = await api<OperatorSession>('/api/auth/login', { method: 'POST', body: JSON.stringify(input) });
    csrfState = null;
    return session;
  },
  logout: async () => {
    await api<void>('/api/auth/logout', { method: 'POST' });
    csrfState = null;
  },
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
