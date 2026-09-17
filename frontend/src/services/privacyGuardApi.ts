export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DecisionType = 'ALLOW' | 'REDACT' | 'DENY';
export type ProposalStatus = 'PENDING' | 'EVALUATED' | 'REMEDIATION_AUTHORIZED' | 'REMEDIATED';
export type DelegationState = 'ACTIVE' | 'SCHEDULED' | 'REVOKED' | 'NOT_GRANTED' | 'UNKNOWN';
export type EffectiveDelegationState = 'ACTIVE' | 'DENIED' | 'UNKNOWN';
export type AgentRegistrationState = 'REGISTERED' | 'NOT_REGISTERED' | 'MISMATCH' | 'UNAVAILABLE';
export type EnterpriseIntegrationState = 'READY' | 'INCOMPLETE' | 'MISMATCH' | 'UNKNOWN';
export type EnterpriseIntegrationDiagnosticCode =
  | 'NONE'
  | 'POLICY_UNAVAILABLE'
  | 'POLICY_INVALID'
  | 'PRIVATE_CONFIGURATION_UNAVAILABLE'
  | 'ENDPOINT_CONFIGURATION_INVALID'
  | 'DELEGATION_UNAVAILABLE'
  | 'INSUFFICIENT_CREDIT'
  | 'T3N_CONTROL_PLANE_UNAVAILABLE';
export type EvidenceScenarioStatus = 'PASS' | 'FAIL' | 'NOT_RUN';
export type RemediationState = 'EXECUTING' | 'PENDING_VERIFICATION' | 'COMPLETED' | 'UNVERIFIED' | 'FAILED';
export type AuditReconciliationStatus = 'LOCAL_ONLY' | 'T3N_ONLY' | 'MATCHED' | 'UNMATCHED';
export type AuditIntegrityState = 'VERIFIED' | 'BROKEN' | 'KEY_MISMATCH' | 'LEGACY_UNVERIFIED' | 'PURGED' | 'NOT_AVAILABLE';
export type HumanAuthority = 'ANALYST' | 'APPROVER' | 'EXECUTOR' | 'AUDITOR';
export type BusinessImpactWindow = 'retained' | '24h' | '7d';
export type IncidentOriginType = 'APPLICATION' | 'EXTERNAL';
export type IncidentWorkspaceStage =
  | 'NEEDS_ANALYSIS'
  | 'POLICY_EVALUATION_REQUIRED'
  | 'POLICY_BLOCKED'
  | 'HUMAN_APPROVAL_REQUIRED'
  | 'POLICY_REVIEWED'
  | 'AUTHORIZED_EXECUTION_PENDING'
  | 'EXECUTION_IN_PROGRESS'
  | 'VERIFICATION_PENDING'
  | 'VERIFIED_COMPLETE'
  | 'UNVERIFIED_REVIEW_REQUIRED'
  | 'FAILED_REVIEW_REQUIRED'
  | 'STATE_UNAVAILABLE';

export interface Incident { id: string; title: string; severity: Severity; summary: string; source: string; status: string; createdAt: string; expiresAt: string; retentionState: 'ACTIVE'; }
export interface IncidentWorkspaceItem {
  id: string;
  title: string;
  severity: Severity;
  source: string;
  originType: IncidentOriginType;
  incidentStatus: string;
  createdAt: string;
  latestActionId?: string | null;
  latestAction?: string | null;
  latestActionStatus?: ProposalStatus | null;
  policyDecision?: DecisionType | null;
  remediationState?: RemediationState | null;
  stage: IncidentWorkspaceStage;
  nextRequiredAction: string;
  requiresAttention: boolean;
}
export interface IncidentWorkspace { generatedAt: string; attentionCount: number; incidents: IncidentWorkspaceItem[]; }
export interface ActionProposal { id: string; incidentId: string; requestId: string; action: string; resource: string; purpose: string; host?: string | null; fields: string[]; normalPayload?: Record<string, string>; privateRefs: string[]; status: ProposalStatus; createdAt: string; remediationAuthorizedBy?: string | null; remediationAuthorizedAt?: string | null; }
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
export interface AuditIntegrity { state: AuditIntegrityState; eventsChecked: number; head?: string | null; version?: string | null; detail: string; }
export interface AuditEvidence { localEvents: LocalAuditEvidence[]; t3nEvents: T3nActivityEvidence[]; provenance: AuditProvenance; integrity: AuditIntegrity; nextSequence?: number | null; limit: number; }
export interface ExecutionTraceEvent { id: string; incidentId: string; actionId: string; traceId: string; requestId: string; stage: string; state: string; reasonCode?: string | null; durationMs?: number | null; createdAt: string; }
export interface OperatorSession { authenticated: boolean; username?: string | null; authorities?: HumanAuthority[]; enterpriseSeparationOfDuties?: boolean; }
export interface AgentAnalysis { provider: string; model: string; incident: Incident; action: ActionProposal; decision: PolicyDecision; }
export interface RemediationExecution { incidentId: string; actionId: string; requestId: string; state: RemediationState; httpCode?: number | null; operationId?: string | null; verificationAttempts: number; failureCode?: string | null; startedAt: string; completedAt?: string | null; executionPrincipal?: string | null; }
export interface BusinessImpact {
  window: 'RETAINED' | '24H' | '7D';
  from: string;
  to: string;
  retentionLimited: boolean;
  evaluatedActions: number;
  deniedBeforeEgress: number;
  minimizedDecisions: number;
  redactedNormalFieldNames: number;
  redactedPrivateRefs: number;
  humanAuthorizedRemediations: number;
  verifiedCompleted: number;
  unverified: number;
  failed: number;
  finalizedExecutions: number;
  blockedRatePct?: number | null;
  verifiedCompletionRatePct?: number | null;
  medianDecisionMs?: number | null;
  medianVerifiedOutcomeMs?: number | null;
}
export interface EnterpriseVerificationContract { action: string; expectedState: string; }
export interface SystemStatus {
  gatewayReachable: boolean;
  tenantAuthenticated: boolean;
  network?: string | null;
  tenantDid?: string | null;
  agentConfigured: boolean;
  agentAuthenticated: boolean;
  agentDid?: string | null;
  executorConfigured: boolean;
  executorAuthenticated: boolean;
  executorDid?: string | null;
  agentRegistrationState: AgentRegistrationState;
  agentCardUri?: string | null;
  agentCardSha256?: string | null;
  agentCardVerifiedAt?: string | null;
  agentCardServices: string[];
  a2aConfigured: boolean;
  a2aPublicUrl?: string | null;
  a2aConfigurationCheckedAt?: string | null;
  contractResolved: boolean;
  contractId?: string | null;
  contractVersion?: string | null;
  evaluationReady: boolean;
  protectedRemediationReady: boolean;
  enterpriseIntegrationState: EnterpriseIntegrationState;
  enterpriseIntegrationDiagnosticCode?: EnterpriseIntegrationDiagnosticCode;
  enterpriseIntegrationReady: boolean;
  firstPartyRemediationAdapterConfigured: boolean;
  enterpriseExecutionConfigured: boolean | null;
  enterpriseVerificationConfigured: boolean | null;
  enterpriseCredentialConfigured: boolean | null;
  enterpriseExecutionHost?: string | null;
  enterpriseVerificationHost?: string | null;
  enterprisePolicyAllowsExecutionHost: boolean | null;
  enterprisePolicyAllowsVerificationHost: boolean | null;
  enterpriseExecutorDelegationAllowsExecutionHost: boolean | null;
  enterpriseExecutorDelegationAllowsVerificationHost: boolean | null;
  enterpriseSupportedExecutableActions: string[];
  enterpriseSupportedVerifiedActions: string[];
  enterpriseVerificationContracts: EnterpriseVerificationContract[];
  enterpriseEvaluationOnlyActions: string[];
  enterpriseIntegrationCheckedAt?: string | null;
  delegationMemberState: DelegationState;
  delegationEffectiveState: EffectiveDelegationState;
  delegatedFunctions: string[];
  delegatedScopes: string[];
  allowedHosts: string[];
  delegationCheckedFunctions: string[];
  delegationCheckedScopes: string[];
  executorDelegationMemberState: DelegationState;
  executorDelegationEffectiveState: EffectiveDelegationState;
  executorDelegatedFunctions: string[];
  executorDelegatedScopes: string[];
  executorAllowedHosts: string[];
  executorDelegationCheckedFunctions: string[];
  executorDelegationCheckedScopes: string[];
  message: string;
}
export interface EvidenceMetadata {
  source: 'T3N_TESTNET';
  generatedAt: string;
  sourceCommitSha: string;
  sourceTreeClean: boolean;
  network: string;
  sdkVersion: string;
  tenantDid: string;
  agentDid: string;
  executorDid: string;
  agentRegistrationState: AgentRegistrationState;
  agentCardUri?: string | null;
  agentCardSha256?: string | null;
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
let operatorSessionState: OperatorSession | null = null;

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

async function loadSession(path: string, init?: RequestInit): Promise<OperatorSession> {
  const session = await api<OperatorSession>(path, init);
  operatorSessionState = session;
  return session;
}

export const privacyGuardApi = {
  session: () => loadSession('/api/auth/session'),
  currentSession: () => operatorSessionState,
  login: async (input: { username: string; password: string }) => { const session = await loadSession('/api/auth/login', { method: 'POST', body: JSON.stringify(input) }); csrfState = null; return session; },
  logout: async () => { await api<void>('/api/auth/logout', { method: 'POST' }); csrfState = null; operatorSessionState = null; },
  systemStatus: () => api<SystemStatus>('/api/system/status'),
  latestEvidence: () => api<EvidenceBundle>('/api/evidence/latest'),
  businessImpact: (window: BusinessImpactWindow = 'retained') => api<BusinessImpact>(`/api/business-impact?window=${encodeURIComponent(window)}`),
  incidentWorkspace: () => api<IncidentWorkspace>('/api/incident-workspace'),
  analyzeAgent: (prompt: string) => api<AgentAnalysis>('/api/agent/analyze', { method: 'POST', body: JSON.stringify({ prompt }) }),
  analyzeAgentInIncident: (incidentId: string, prompt: string) => api<AgentAnalysis>(`/api/incidents/${encodeURIComponent(incidentId)}/agent-proposals`, { method: 'POST', body: JSON.stringify({ prompt }) }),
  listIncidents: () => api<Incident[]>('/api/incidents'),
  getIncident: (id: string) => api<Incident>(`/api/incidents/${encodeURIComponent(id)}`),
  createIncident: (input: { title: string; severity: Severity; summary: string; source: string }) => api<Incident>('/api/incidents', { method: 'POST', body: JSON.stringify(input) }),
  listActions: (incidentId: string) => api<ActionProposal[]>(`/api/incidents/${encodeURIComponent(incidentId)}/actions`),
  createAction: (incidentId: string, input: { requestId: string; action: string; resource: string; purpose: string; host?: string; fields: string[]; privateRefs?: string[] }) => api<ActionProposal>(`/api/incidents/${encodeURIComponent(incidentId)}/actions`, { method: 'POST', body: JSON.stringify(input) }),
  evaluate: (incidentId: string, actionId: string) => api<PolicyDecision>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/evaluate`, { method: 'POST' }),
  getDecision: (incidentId: string, actionId: string) => api<PolicyDecision>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/decision`),
  authorizeRemediation: (incidentId: string, actionId: string) => api<{ incidentId: string; actionId: string; requestId: string; state: ProposalStatus; authorizedBy: string; authorizedAt: string }>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/authorize-remediation`, { method: 'POST' }),
  getRemediation: (incidentId: string, actionId: string) => api<RemediationExecution>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/remediation`),
  executeRemediation: (incidentId: string, actionId: string) => api<RemediationExecution>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/execute-remediation`, { method: 'POST' }),
  verifyRemediation: (incidentId: string, actionId: string) => api<RemediationExecution>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/verify-remediation`, { method: 'POST' }),
  executionTrace: (incidentId: string, actionId: string) => api<ExecutionTraceEvent[]>(`/api/incidents/${encodeURIComponent(incidentId)}/actions/${encodeURIComponent(actionId)}/trace`),
  history: (incidentId: string) => api<AuditEvent[]>(`/api/incidents/${encodeURIComponent(incidentId)}/history`),
  auditEvidence: (incidentId: string, limit = 100) => api<AuditEvidence>(`/api/incidents/${encodeURIComponent(incidentId)}/audit-evidence?limit=${encodeURIComponent(String(limit))}`),
};
