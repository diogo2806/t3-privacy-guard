import { useCallback, useEffect, useState } from 'react';
import {
  PrivacyGuardApiError,
  privacyGuardApi,
  type ActionProposal,
  type AgentAnalysis,
  type AuditEvent,
  type EvidenceBundle,
  type ExecutionTraceEvent,
  type Incident,
  type OperatorSession,
  type PolicyDecision,
  type RemediationExecution,
  type SystemStatus,
} from '../../services/privacyGuardApi';
import { ActionProposalPanel } from '../actions/ActionProposalPanel';
import { AgentPromptPanel } from '../agent/AgentPromptPanel';
import { AgentProposalPanel } from '../agent/AgentProposalPanel';
import { OperatorSessionGate } from '../auth/OperatorSessionGate';
import { AuditTrail } from '../audit/AuditTrail';
import { ExecutionTrace } from '../audit/ExecutionTrace';
import { DashboardTabs, type DashboardView } from './DashboardTabs';
import { EvidenceCenter } from '../evidence/EvidenceCenter';
import { IncidentSummary } from '../incidents/IncidentSummary';
import { AppHeader } from '../layout/AppHeader';
import { DecisionPanel } from '../policy/DecisionPanel';
import { RemediationPanel } from '../remediation/RemediationPanel';
import { EnterpriseScenarioCatalog } from '../scenarios/EnterpriseScenarioCatalog';
import { DEFAULT_ENTERPRISE_SCENARIO, ENTERPRISE_SCENARIOS, type EnterpriseScenarioDefinition } from '../scenarios/scenarioDefinitions';
import { EmptyState } from '../states/EmptyState';
import { SystemStatusBar } from '../status/SystemStatusBar';
import { NextRequiredAction } from '../trust/NextRequiredAction';
import { TrustFlowSummary } from '../trust/TrustFlowSummary';

function requestId(prefix: string) { return `${prefix}-${crypto.randomUUID()}`; }

export function PrivacyGuardDashboard() {
  const [session, setSession] = useState<OperatorSession | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [authRetryAfterSeconds, setAuthRetryAfterSeconds] = useState(0);

  useEffect(() => {
    void privacyGuardApi.session().then(setSession).catch(() => setSession({ authenticated: false })).finally(() => setSessionLoading(false));
  }, []);

  const login = async (credentials: { username: string; password: string }) => {
    setAuthBusy(true); setAuthError(null); setAuthRetryAfterSeconds(0);
    try { setSession(await privacyGuardApi.login(credentials)); }
    catch (cause) {
      setSession({ authenticated: false });
      if (cause instanceof PrivacyGuardApiError && cause.status === 429) {
        setAuthRetryAfterSeconds(cause.retryAfterSeconds ?? 5);
      } else {
        setAuthError(cause instanceof Error ? cause.message : 'Unable to sign in.');
      }
    }
    finally { setAuthBusy(false); }
  };

  const logout = async () => {
    setAuthBusy(true); setAuthError(null); setAuthRetryAfterSeconds(0);
    try { await privacyGuardApi.logout(); setSession({ authenticated: false }); }
    catch (cause) { setAuthError(cause instanceof Error ? cause.message : 'Unable to sign out safely.'); }
    finally { setAuthBusy(false); }
  };

  const expireSession = useCallback(() => {
    setSession({ authenticated: false });
    setAuthRetryAfterSeconds(0);
    setAuthError('Your operator session has expired. Sign in again to continue.');
  }, []);

  return (
    <div className="app-shell">
      <AppHeader />
      <OperatorSessionGate session={session} loading={sessionLoading} busy={authBusy} error={authError} retryAfterSeconds={authRetryAfterSeconds} onLogin={login} onLogout={logout} />
      {session?.authenticated && <AuthenticatedDashboard onSessionExpired={expireSession} />}
    </div>
  );
}

function AuthenticatedDashboard({ onSessionExpired }: { onSessionExpired: () => void }) {
  const [view, setView] = useState<DashboardView>('demo');
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [selectedScenarioId, setSelectedScenarioId] = useState(DEFAULT_ENTERPRISE_SCENARIO.id);
  const [prompt, setPrompt] = useState(DEFAULT_ENTERPRISE_SCENARIO.prompt);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [actions, setActions] = useState<ActionProposal[]>([]);
  const [selectedAction, setSelectedAction] = useState<ActionProposal | null>(null);
  const [decision, setDecision] = useState<PolicyDecision | null>(null);
  const [agentAnalysis, setAgentAnalysis] = useState<AgentAnalysis | null>(null);
  const [remediationExecution, setRemediationExecution] = useState<RemediationExecution | null>(null);
  const [executionTrace, setExecutionTrace] = useState<ExecutionTraceEvent[]>([]);
  const [history, setHistory] = useState<AuditEvent[]>([]);
  const [evidence, setEvidence] = useState<EvidenceBundle | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const selectedScenario = ENTERPRISE_SCENARIOS.find((scenario) => scenario.id === selectedScenarioId) ?? DEFAULT_ENTERPRISE_SCENARIO;

  const handleError = useCallback((cause: unknown, fallback: string) => {
    if (cause instanceof PrivacyGuardApiError && cause.status === 401) { onSessionExpired(); return; }
    setError(cause instanceof Error ? cause.message : fallback);
  }, [onSessionExpired]);

  const refreshSystem = useCallback(async () => {
    setStatusLoading(true);
    try { setSystemStatus(await privacyGuardApi.systemStatus()); }
    catch (cause) { setSystemStatus(null); handleError(cause, 'Unable to load system status.'); }
    finally { setStatusLoading(false); }
  }, [handleError]);

  const refreshEvidence = useCallback(async () => {
    setEvidenceLoading(true); setEvidenceError(null);
    try { setEvidence(await privacyGuardApi.latestEvidence()); }
    catch (cause) {
      setEvidence(null);
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired();
      else if (cause instanceof PrivacyGuardApiError && cause.status === 404) setEvidenceError('No live T3N evidence has been generated yet.');
      else setEvidenceError(cause instanceof Error ? cause.message : 'Evidence could not be loaded safely.');
    } finally { setEvidenceLoading(false); }
  }, [onSessionExpired]);

  const loadDecision = useCallback(async (currentIncident: Incident, action: ActionProposal) => {
    if (action.status === 'PENDING') { setDecision(null); return; }
    try { setDecision(await privacyGuardApi.getDecision(currentIncident.id, action.id)); }
    catch (cause) { if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired(); else setDecision(null); }
  }, [onSessionExpired]);

  const loadRemediation = useCallback(async (currentIncident: Incident, action: ActionProposal) => {
    try { setRemediationExecution(await privacyGuardApi.getRemediation(currentIncident.id, action.id)); }
    catch (cause) {
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired();
      else setRemediationExecution(null);
    }
  }, [onSessionExpired]);

  const loadExecutionTrace = useCallback(async (currentIncident: Incident, action: ActionProposal) => {
    try { setExecutionTrace(await privacyGuardApi.executionTrace(currentIncident.id, action.id)); }
    catch (cause) {
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired();
      else setExecutionTrace([]);
    }
  }, [onSessionExpired]);

  const refreshIncident = useCallback(async (currentIncident: Incident, preferredActionId?: string) => {
    const [currentActions, currentHistory] = await Promise.all([privacyGuardApi.listActions(currentIncident.id), privacyGuardApi.history(currentIncident.id)]);
    setActions(currentActions); setHistory(currentHistory);
    const selected = currentActions.find((item) => item.id === preferredActionId) ?? currentActions.at(-1) ?? null;
    setSelectedAction(selected);
    if (selected) await Promise.all([loadDecision(currentIncident, selected), loadRemediation(currentIncident, selected), loadExecutionTrace(currentIncident, selected)]);
    else { setDecision(null); setRemediationExecution(null); setExecutionTrace([]); }
  }, [loadDecision, loadExecutionTrace, loadRemediation]);

  useEffect(() => {
    void refreshSystem();
    void privacyGuardApi.listIncidents().then(async (items) => {
      const current = items[0] ?? null; setIncident(current); if (current) await refreshIncident(current);
    }).catch((cause) => handleError(cause, 'Unable to load incidents.'));
  }, [handleError, refreshIncident, refreshSystem]);

  useEffect(() => { if (view === 'evidence' && !evidence && !evidenceLoading) void refreshEvidence(); }, [view, evidence, evidenceLoading, refreshEvidence]);

  const run = async (operation: () => Promise<void>) => {
    setBusy(true); setError(null); setNotice(null);
    try { await operation(); } catch (cause) { handleError(cause, 'The operation could not be completed safely.'); } finally { setBusy(false); }
  };

  const analyzeAgentPrompt = (currentPrompt: string) => run(async () => {
    const result = await privacyGuardApi.analyzeAgent(currentPrompt);
    setAgentAnalysis(result); setRemediationExecution(null); setIncident(result.incident); setSelectedAction(result.action); setDecision(result.decision);
    await refreshIncident(result.incident, result.action.id);
    if (result.decision.decision === 'DENY') setNotice('The independent T3N policy blocked the agent proposal before protected egress.');
    else if (result.decision.decision === 'REDACT') setNotice('T3N requires data minimization before the proposal can continue.');
    else setNotice('T3N policy allowed the proposal to continue. ALLOW is not authorization or execution.');
  });

  const selectScenario = (scenario: EnterpriseScenarioDefinition) => {
    setSelectedScenarioId(scenario.id);
    setPrompt(scenario.prompt);
    setAgentAnalysis(null);
    setIncident(null);
    setActions([]);
    setSelectedAction(null);
    setDecision(null);
    setRemediationExecution(null);
    setExecutionTrace([]);
    setHistory([]);
    setError(null);
    setNotice(`${scenario.title} loaded with synthetic demo data. No API call or authorization has occurred yet.`);
  };

  const prepareSafeRemediation = () => run(async () => {
    if (!incident || selectedScenario.id !== 'credential-compromised') return;
    const safeAction = await privacyGuardApi.createAction(incident.id, { requestId: requestId('remediation'), action: 'revoke-credential', resource: 'credential:production-security-api', purpose: 'incident-remediation', host: 'postman-echo.com', fields: ['incident_id', 'credential_id', 'reason'] });
    const result = await privacyGuardApi.evaluate(incident.id, safeAction.id);
    setRemediationExecution(null); await refreshIncident(incident, safeAction.id); setDecision(result);
    setNotice(result.decision === 'ALLOW' ? 'Minimum-scope revocation passed policy. Human authorization is still required before protected execution.' : `Credential revocation received ${result.decision}; execution remains blocked.`);
  });

  const retryEvaluation = () => run(async () => {
    if (!incident || !selectedAction) return;
    const result = await privacyGuardApi.evaluate(incident.id, selectedAction.id);
    setDecision(result);
    await refreshIncident(incident, selectedAction.id);
  });

  const authorize = () => run(async () => {
    if (!incident || !selectedAction) return;
    await privacyGuardApi.authorizeRemediation(incident.id, selectedAction.id); await refreshIncident(incident, selectedAction.id);
    setNotice('Human authorization recorded. Protected execution still requires the bound executor and one-time proof.');
  });

  const executionNotice = (result: RemediationExecution) => {
    if (result.state === 'COMPLETED') return 'Independent read-back verified the expected external state. Remediation is COMPLETED.';
    if (result.state === 'PENDING_VERIFICATION') return 'External execution was accepted. Completion is still pending independent verification.';
    if (result.state === 'UNVERIFIED') return 'The external outcome is unverified. No automatic re-execution will occur; use Verify external state when an operation id is available.';
    if (result.state === 'FAILED') return 'Execution failed without verified completion. Review the audit trail before creating a new action.';
    return 'Execution has been claimed and is in progress. A retry will reconcile this claim instead of sending a second side effect.';
  };

  const execute = () => run(async () => {
    if (!incident || !selectedAction) return;
    const result = await privacyGuardApi.executeRemediation(incident.id, selectedAction.id);
    setRemediationExecution(result); await refreshIncident(incident, selectedAction.id); setNotice(executionNotice(result));
  });

  const verifyExternalState = () => run(async () => {
    if (!incident || !selectedAction) return;
    const result = await privacyGuardApi.verifyRemediation(incident.id, selectedAction.id);
    setRemediationExecution(result); await refreshIncident(incident, selectedAction.id); setNotice(executionNotice(result));
  });

  const selectAction = (action: ActionProposal) => {
    setSelectedAction(action);
    if (incident) void Promise.all([loadDecision(incident, action), loadRemediation(incident, action), loadExecutionTrace(incident, action)]);
    else { setDecision(null); setRemediationExecution(null); setExecutionTrace([]); }
  };

  const showSafePath = selectedScenario.id === 'credential-compromised' && decision?.decision === 'DENY' && Boolean(incident);

  return (
    <>
      <TrustFlowSummary
        agentAnalysis={agentAnalysis}
        decision={decision}
        selectedAction={selectedAction}
        remediationExecution={remediationExecution}
        systemStatus={systemStatus}
        statusLoading={statusLoading}
        busy={busy}
        onRetryEvaluation={() => void retryEvaluation()}
      />
      <details className="readiness-disclosure">
        <summary>System readiness details</summary>
        <SystemStatusBar status={systemStatus} loading={statusLoading} onRefresh={() => void refreshSystem()} />
      </details>
      <DashboardTabs active={view} onChange={setView} />
      {error && <div className="feedback feedback-error" role="alert">{error}</div>}
      {notice && <div className="feedback feedback-success" role="status">{notice}</div>}

      {view === 'evidence' ? (
        <EvidenceCenter evidence={evidence} loading={evidenceLoading} error={evidenceError} onRefresh={() => void refreshEvidence()} />
      ) : (
        <main className="dashboard-grid">
          <div className="dashboard-main">
            <EnterpriseScenarioCatalog selectedId={selectedScenarioId} busy={busy} onSelect={selectScenario} />
            <AgentPromptPanel busy={busy} prompt={prompt} onPromptChange={setPrompt} onAnalyze={analyzeAgentPrompt} />
            <AgentProposalPanel analysis={agentAnalysis} />
            {!incident ? <EmptyState /> : <>
              <IncidentSummary incident={incident} />
              {showSafePath && <NextRequiredAction busy={busy} onPrepareSafePath={() => void prepareSafeRemediation()} />}
              <div className="two-column"><ActionProposalPanel actions={actions} selectedActionId={selectedAction?.id ?? null} onSelect={selectAction} /><DecisionPanel decision={decision} /></div>
              <RemediationPanel action={selectedAction} decision={decision} execution={remediationExecution} busy={busy} onAuthorize={authorize} onExecute={execute} onVerify={verifyExternalState} />
            </>}
          </div>
          <aside className="dashboard-side" aria-label="Live activity"><ExecutionTrace events={executionTrace} action={selectedAction} /><AuditTrail events={history} /></aside>
        </main>
      )}
    </>
  );
}
