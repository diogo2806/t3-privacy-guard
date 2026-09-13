export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DecisionType = 'ALLOW' | 'REDACT' | 'DENY';
export type ProposalStatus = 'PENDING' | 'EVALUATED' | 'REMEDIATION_AUTHORIZED' | 'REMEDIATED';
export type DelegationState = 'ACTIVE' | 'REVOKED' | 'NOT_GRANTED' | 'UNKNOWN';
export type AgentRegistrationState = 'REGISTERED' | 'NOT_REGISTERED' | 'MISMATCH' | 'UNAVAILABLE';
export type EvidenceScenarioStatus = 'PASS' | 'FAIL' | 'NOT_RUN';
export type RemediationState = 'EXECUTING' | 'PENDING_VERIFICATION' | 'COMPLETED' | 'UNVERIFIED' | 'FAILED';
export type AuditReconciliationStatus = 'LOCAL_ONLY' | 'T3N_ONLY' | 'MATCHED' | 'UNMATCHED';

export interface Incident { id: string; title: string; severity: Severity; summary: string; source: string; status: string; createdAt: string; expiresAt: string; retentionState: 'ACTIVE'; }
export interface ActionProposal { id: string; incidentId: string; requestId: string; action: string; resource: string; purpose: string; host?: string | null; fields: string[]; privateRefs: string[]; status: ProposalStatus; createdAt: string; }
export interface PolicyDecision {
  id: string;
  actionProposalId: string;
  decision: DecisionType;
  reasonCode: string;
  reason: string;
  allowedFields: string[];
  redactedFields: string[];
  allowedPrivateRefs: string[];
  redactedPrivateRefs: string[];
  policyVersion?: string | null;
  policyHash?: string | null;
  requiresHumanAuthorization?: boolean | null;
  evaluatedAt: string;
}
export interface AuditEvent { id: string; incidentId: string; type: string; message: string; createdAt: string; }
export interface LocalAuditEvidence extends AuditEvent { status: AuditReconciliationStatus; t3nSequence?: number | null; t3nFunction?: string | null; matchedSequence?: number | null; }
export interface T3nActivityEvidence { sequence: number; hash: string; timestamp: string; callerType: string; actorDid: string; onBehalfOfDid: string; contractId: string; function: string; outcome: string; status: AuditReconciliationStatus; }
export interface AuditProvenance { localAvailable: boolean; t3nAvailable: boolean; t3nComplete: boolean; matched: number; unmatched: number; localOnly: number; t3nOnly: number; message: string; }
export interface AuditEvidence { localEvents: LocalAuditEvidence[]; t3nEvents: T3nActivityEvidence[]; provenance: AuditProvenance; nextSequence?: number | null; limit: number; }
export interface ExecutionTraceEvent { id: string; incidentId: string; actionId: string; traceId: string; requestId: string; stage: string; state: string; reasonCode?: string | null; durationMs?: number | null; createdAt: string; }
export interface OperatorSession { authenticated: boolean; username?: string | null; }
export interface AgentAnalysis { provider: string; model: string; incident: Incident; action: ActionProposal; decision: PolicyDecision; }
export interface RemediationExecution { incidentId: string; actionId: string; requestId: string; state: RemediationState; httpCode?: number | null; operationId?: string | null; verificationAttempts: number; failureCode?: string | null; startedAt: string; completedAt?: string | null; }
export interface SystemStatus {
  gatewayReachable: boolean;
  tenantAuthenticated: boolean;
  network?: string | null;
  tenantDid?: string | null;
  agentConfigured: boolean;
  agentAuthenticated: boolean;
  agentDid?: string | null;
  agentRegistrationState?: AgentRegistrationState;
  agentCardUri?: string | null;
  agentCardSha256?: string | null;
  agentCardVerifiedAt?: string | null;
  agentCardServices?: string[];
  contractResolved: boolean;
  contractId?: string | null;
  contractVersion?: string | null;
  delegationState: DelegationState;
  delegatedFunctions: string[];
  allowedHosts: string[];
  message: string;
}
export interface EvidenceMetadata {
  source: 'T3N_TESTNET';
  generatedAt: string;
  network: string;
  sdkVersion: string;
  tenantDid: string;
  agentDid: string;
  agentRegistrationState: AgentRegistrationState;
  agentCardUri: string;
  agentCardSha256: string;
  agentCardVerifiedAt: string;
  agentCardServices: string[];
  contractId: string;
  contractVersion: string;
  wasmSha256: string;
  policyVersion: string;
  policyHash: string;
  trustAnchorVerified: boolean;
  trustManifestFloorPersisted: boolean;
  trustManifestVersion: number;
}
export interface EvidenceScenario { id: string; expected: string; actual?: string | null; status: EvidenceScenarioStatus; detail?: string | null; }
export interface EvidenceBundle { metadata: EvidenceMetadata; scenarios: EvidenceScenario[]; totals: { pass: number; fail: number; notRun: number }; }

interface CsrfState { token: string; headerName: string; }
let csrfState: CsrfState | null = null;

export class PrivacyGuardApiError extends Error {
  constructor(message: string, readonly status: number, readonly retryAfterSeconds?: number) { super(message); this.name = 'PrivacyGuardApiError'; }
}

async function readProblem(response: Response): Promise<string> {
  let message = `Request failed with status ${response.status}.`;
  try {
    const problem = await response.json() as { detail?: string; title?: string; error?: string };
    message = problem.detail || problem.title || problem.error || message;
  } catch { /* Keep sanitized generic status message. */ }
  return message;
}

function retryAfterSeconds(response: Response): number | undefined {
  const raw = response.headers.get('Retry-After');
  if (!raw) return undefined;
  const seconds = Number(raw);
  return Number.isInteger(seconds) && seconds > 0 && seconds <= 3600 ? seconds : undefined;
}

async function ensureCsrf(): Promise<CsrfState> {
  if (csrfState) return csrfState;
  const response = await fetch('/api/auth/csrf', { credentials: 'same-origin' });
  if (!response.ok) throw new PrivacyGuardApiError(await readProblem(response), response.status, retryAfterSeconds(response));
  csrfState = await response.json() as CsrfState;
  return csrfState;
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? 'GET').toUpperCase();
  const headers = new Headers(init?.headers);
  if (!headers.has('X-Trace-Id')) headers.set('X-Trace-Id', crypto.randomUUID());
  if (init?.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = await ensureCsrf();
    headers.set(csrf.headerName, csrf.token);
  }
  const response = await fetch(path, { ...init, method, headers, credentials: 'same-origin' });
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) csrfState = null;
    throw new PrivacyGuardApiError(await readProblem(response), response.status, retryAfterSeconds(response));
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const privacyGuardApi = {
  session: () => api<OperatorSession>('/api/auth/session'),
  login: async (input: { username: string; password: string }) => { const session = await api<OperatorSession>('/api/auth/login', { method: 'POST', body: JSON.stringify(input) }); csrfState = null; return session; },
  logout: async () => { await api<void>('/api/auth/logout', { method: 'POST' }); csrfState = null; },
  systemStatus: () => api<SystemStatus>('/api/system/status'),
  latestEvidence: () => api<EvidenceBundle>('/api/evidence/latest'),
  analyzeAgent: (prompt: string) => api<AgentAnalysis>('/api/agent/analyze', { method: 'POST', body: JSON.stringify({ prompt }) }),
  listIncidents: () => api<Incident[]>('/api/incidents'),
  getIncident: (id: string) => api<Incident>(`/api/incidents/${encodeURIComponent(id)}`),
  createIncident: (input: { title: string; severity: Severity; summary: string; source: string }) => api<Incident>('/api/incidents', { method: 'POST', body: JSON.stringify(input) }),
  listActions: (incidentId: string) => api<ActionProposal[]>(`/api/incidents/${encodeURIComponent(incidentId)}/actions`),
  createAction: (incidentId: string, input: { requestId: string; action: string; resource: string; purpose: string; host?: string; fields: string[]; privateRefs?: string[] }) => api<ActionProposal>(`/api/incidents/${encodeURIComponent(incidentId)}/actions`, { method: 'POST', body: JSON.stringify(input) }),
  evaluate: (incidentId: string, actionId: string) => api<PolicyDecision>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/evaluate`, { method: 'POST' }),
  getDecision: (incidentId: string, actionId: string) => api<PolicyDecision>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/decision`),
  authorizeRemediation: (incidentId: string, actionId: string) => api<{ incidentId: string; actionId: string; requestId: string; state: ProposalStatus }>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/authorize-remediation`, { method: 'POST' }),
  getRemediation: (incidentId: string, actionId: string) => api<RemediationExecution>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/remediation`),
  executeRemediation: (incidentId: string, actionId: string) => api<RemediationExecution>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/execute-remediation`, { method: 'POST' }),
  verifyRemediation: (incidentId: string, actionId: string) => api<RemediationExecution>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/verify-remediation`, { method: 'POST' }),
  executionTrace: (incidentId: string, actionId: string) => api<ExecutionTraceEvent[]>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/trace`),
  history: (incidentId: string) => api<AuditEvent[]>(`/api/incidents/${encodeURIComponent(incidentId)}/history`),
  auditEvidence: (incidentId: string, limit = 100) => api<AuditEvidence>(`/api/incidents/${encodeURIComponent(incidentId)}/audit-evidence?limit=${encodeURIComponent(String(limit))}`),
};
