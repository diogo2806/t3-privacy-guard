import { useCallback, useEffect, useRef, useState } from 'react';
import {
  PrivacyGuardApiError,
  privacyGuardApi,
  type ActionProposal,
  type AgentAnalysis,
  type AuditEvent,
  type BusinessImpact,
  type BusinessImpactWindow,
  type EvidenceBundle,
  type ExecutionTraceEvent,
  type Incident,
  type IncidentWorkspace,
  type IncidentWorkspaceItem,
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
import { BusinessOutcomeSummary } from '../business/BusinessOutcomeSummary';
import { ControlImpactSummary } from '../business/ControlImpactSummary';
import { ExecutiveDemoView } from '../demo/ExecutiveDemoView';
import { EvidenceCenter } from '../evidence/EvidenceCenter';
import { IncidentSummary } from '../incidents/IncidentSummary';
import { IncidentWorkspaceQueue } from '../incidents/IncidentWorkspaceQueue';
import { AppHeader } from '../layout/AppHeader';
import { DecisionPanel } from '../policy/DecisionPanel';
import { RemediationPanel } from '../remediation/RemediationPanel';
import { EnterpriseScenarioCatalog } from '../scenarios/EnterpriseScenarioCatalog';
import { DEFAULT_ENTERPRISE_SCENARIO, ENTERPRISE_SCENARIOS, type EnterpriseScenarioDefinition } from '../scenarios/scenarioDefinitions';
import { EmptyState } from '../states/EmptyState';
import { SystemStatusBar } from '../status/SystemStatusBar';
import { NextRequiredAction } from '../trust/NextRequiredAction';
import { TrustFlowSummary } from '../trust/TrustFlowSummary';
import { DashboardTabs, type DashboardView } from './DashboardTabs';

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
  const [incidentScenarioId, setIncidentScenarioId] = useState<string | null>(null);
  const [prompt, setPrompt] = useState(DEFAULT_ENTERPRISE_SCENARIO.prompt);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [actions, setActions] = useState<ActionProposal[]>([]);
  const [selectedAction, setSelectedAction] = useState<ActionProposal | null>(null);
  const [decision, setDecision] = useState<PolicyDecision | null>(null);
  const [agentAnalysis, setAgentAnalysis] = useState<AgentAnalysis | null>(null);
  const [remediationExecution, setRemediationExecution] = useState<RemediationExecution | null>(null);
  const [executionTrace, setExecutionTrace] = useState<ExecutionTraceEvent[]>([]);
  const [history, setHistory] = useState<AuditEvent[]>([]);
  const [workspace, setWorkspace] = useState<IncidentWorkspace | null>(null);
  const [workspaceLoading, setWorkspaceLoading] = useState(false);
  const [workspaceError, setWorkspaceError] = useState<string | null>(null);
  const [selectedWorkspaceIncidentId, setSelectedWorkspaceIncidentId] = useState<string | null>(null);
  const [incidentDetailLoading, setIncidentDetailLoading] = useState(false);
  const [incidentDetailError, setIncidentDetailError] = useState<string | null>(null);
  const [businessImpact, setBusinessImpact] = useState<BusinessImpact | null>(null);
  const [businessImpactWindow, setBusinessImpactWindow] = useState<BusinessImpactWindow>('retained');
  const [businessImpactLoading, setBusinessImpactLoading] = useState(false);
  const [businessImpactError, setBusinessImpactError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<EvidenceBundle | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const selectionGeneration = useRef(0);

  const selectedScenario = ENTERPRISE_SCENARIOS.find((scenario) => scenario.id === selectedScenarioId) ?? DEFAULT_ENTERPRISE_SCENARIO;
  const incidentScenario = incidentScenarioId ? (ENTERPRISE_SCENARIOS.find((scenario) => scenario.id === incidentScenarioId) ?? null) : null;
  const scenarioContext = incident ? incidentScenario : selectedScenario;

  const isCurrentSelection = useCallback((generation?: number) => generation === undefined || selectionGeneration.current === generation, []);

  const handleError = useCallback((cause: unknown, fallback: string) => {
    if (cause instanceof PrivacyGuardApiError && cause.status === 401) { onSessionExpired(); return; }
    setError(cause instanceof Error ? cause.message : fallback);
  }, [onSessionExpired]);

  const clearIncidentRuntime = useCallback(() => {
    setIncident(null);
    setActions([]);
    setSelectedAction(null);
    setDecision(null);
    setAgentAnalysis(null);
    setRemediationExecution(null);
    setExecutionTrace([]);
    setHistory([]);
  }, []);

  const refreshSystem = useCallback(async () => {
    setStatusLoading(true);
    try { setSystemStatus(await privacyGuardApi.systemStatus()); }
    catch (cause) { setSystemStatus(null); handleError(cause, 'Unable to load system status.'); }
    finally { setStatusLoading(false); }
  }, [handleError]);

  const refreshWorkspace = useCallback(async (): Promise<IncidentWorkspace | null> => {
    setWorkspaceLoading(true); setWorkspaceError(null);
    try {
      const result = await privacyGuardApi.incidentWorkspace();
      setWorkspace(result);
      return result;
    } catch (cause) {
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired();
      else setWorkspaceError(cause instanceof Error ? cause.message : 'Incident workspace could not be loaded safely.');
      return null;
    } finally { setWorkspaceLoading(false); }
  }, [onSessionExpired]);

  const refreshBusinessImpact = useCallback(async () => {
    setBusinessImpactLoading(true); setBusinessImpactError(null);
    try { setBusinessImpact(await privacyGuardApi.businessImpact(businessImpactWindow)); }
    catch (cause) {
      setBusinessImpact(null);
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired();
      else setBusinessImpactError(cause instanceof Error ? cause.message : 'Measured control impact could not be loaded safely.');
    } finally { setBusinessImpactLoading(false); }
  }, [businessImpactWindow, onSessionExpired]);

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

  const loadDecision = useCallback(async (currentIncident: Incident, action: ActionProposal, generation?: number) => {
    if (action.status === 'PENDING') { if (isCurrentSelection(generation)) setDecision(null); return; }
    try {
      const result = await privacyGuardApi.getDecision(currentIncident.id, action.id);
      if (isCurrentSelection(generation)) setDecision(result);
    } catch (cause) {
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired();
      else if (isCurrentSelection(generation)) setDecision(null);
    }
  }, [isCurrentSelection, onSessionExpired]);

  const loadRemediation = useCallback(async (currentIncident: Incident, action: ActionProposal, generation?: number) => {
    try {
      const result = await privacyGuardApi.getRemediation(currentIncident.id, action.id);
      if (isCurrentSelection(generation)) setRemediationExecution(result);
    } catch (cause) {
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired();
      else if (isCurrentSelection(generation)) setRemediationExecution(null);
    }
  }, [isCurrentSelection, onSessionExpired]);

  const loadExecutionTrace = useCallback(async (currentIncident: Incident, action: ActionProposal, generation?: number) => {
    try {
      const result = await privacyGuardApi.executionTrace(currentIncident.id, action.id);
      if (isCurrentSelection(generation)) setExecutionTrace(result);
    } catch (cause) {
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired();
      else if (isCurrentSelection(generation)) setExecutionTrace([]);
    }
  }, [isCurrentSelection, onSessionExpired]);

  const refreshIncident = useCallback(async (currentIncident: Incident, preferredActionId?: string, generation?: number) => {
    const [currentActions, currentHistory] = await Promise.all([privacyGuardApi.listActions(currentIncident.id), privacyGuardApi.history(currentIncident.id)]);
    if (!isCurrentSelection(generation)) return;
    setActions(currentActions); setHistory(currentHistory);
    const selected = currentActions.find((item) => item.id === preferredActionId) ?? currentActions.at(-1) ?? null;
    setSelectedAction(selected);
    if (selected) await Promise.all([
      loadDecision(currentIncident, selected, generation),
      loadRemediation(currentIncident, selected, generation),
      loadExecutionTrace(currentIncident, selected, generation),
    ]);
    else if (isCurrentSelection(generation)) { setDecision(null); setRemediationExecution(null); setExecutionTrace([]); }
  }, [isCurrentSelection, loadDecision, loadExecutionTrace, loadRemediation]);

  const removeWorkspaceIncident = useCallback((incidentId: string) => {
    setWorkspace((current) => {
      if (!current) return current;
      const incidents = current.incidents.filter((item) => item.id !== incidentId);
      return { ...current, incidents, attentionCount: incidents.filter((item) => item.requiresAttention).length };
    });
  }, []);

  const openWorkspaceIncident = useCallback(async (item: IncidentWorkspaceItem) => {
    const generation = selectionGeneration.current + 1;
    selectionGeneration.current = generation;
    setSelectedWorkspaceIncidentId(item.id);
    setIncidentScenarioId(null);
    setIncidentDetailLoading(true);
    setIncidentDetailError(null);
    setError(null);
    setNotice(null);
    clearIncidentRuntime();

    try {
      const currentIncident = await privacyGuardApi.getIncident(item.id);
      if (!isCurrentSelection(generation)) return;
      setIncident(currentIncident);
      await refreshIncident(currentIncident, item.latestActionId ?? undefined, generation);
    } catch (cause) {
      if (!isCurrentSelection(generation)) return;
      clearIncidentRuntime();
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) {
        onSessionExpired();
      } else if (cause instanceof PrivacyGuardApiError && cause.status === 404) {
        removeWorkspaceIncident(item.id);
        setSelectedWorkspaceIncidentId(null);
        setNotice('This incident is no longer active and was removed from the workspace. Select another active incident or run a new scenario.');
      } else {
        setIncidentDetailError(cause instanceof Error ? cause.message : 'Selected incident could not be opened safely.');
      }
    } finally {
      if (isCurrentSelection(generation)) setIncidentDetailLoading(false);
    }
  }, [clearIncidentRuntime, isCurrentSelection, onSessionExpired, refreshIncident, removeWorkspaceIncident]);

  useEffect(() => {
    let active = true;
    void refreshSystem();
    void (async () => {
      const currentWorkspace = await refreshWorkspace();
      if (!active || !currentWorkspace) return;
      const current = currentWorkspace.incidents[0] ?? null;
      if (current) await openWorkspaceIncident(current);
    })();
    return () => { active = false; selectionGeneration.current += 1; };
  }, [openWorkspaceIncident, refreshSystem, refreshWorkspace]);

  useEffect(() => { void refreshBusinessImpact(); }, [refreshBusinessImpact]);

  useEffect(() => {
    const evidenceView = view === 'presentation' || view === 'evidence';
    if (evidenceView && !evidence && !evidenceLoading && !evidenceError) void refreshEvidence();
  }, [view, evidence, evidenceLoading, evidenceError, refreshEvidence]);

  const run = async (operation: () => Promise<void>) => {
    setBusy(true); setError(null); setNotice(null);
    try { await operation(); } catch (cause) { handleError(cause, 'The operation could not be completed safely.'); } finally { setBusy(false); }
  };

  const analyzeAgentPrompt = (currentPrompt: string) => run(async () => {
    const previousGeneration = selectionGeneration.current;
    const result = await privacyGuardApi.analyzeAgent(currentPrompt);
    if (!isCurrentSelection(previousGeneration)) {
      await Promise.all([refreshWorkspace(), refreshBusinessImpact()]);
      return;
    }

    const generation = previousGeneration + 1;
    selectionGeneration.current = generation;
    setSelectedWorkspaceIncidentId(result.incident.id);
    setIncidentScenarioId(selectedScenario.id);
    setAgentAnalysis(result); setRemediationExecution(null); setIncident(result.incident); setSelectedAction(result.action); setDecision(result.decision);
    await Promise.all([refreshIncident(result.incident, result.action.id, generation), refreshBusinessImpact(), refreshWorkspace()]);
    if (!isCurrentSelection(generation)) return;
    if (result.decision.decision === 'DENY') setNotice('The independent T3N policy blocked the agent proposal before protected egress.');
    else if (result.decision.decision === 'REDACT') setNotice('T3N requires data minimization before the proposal can continue.');
    else setNotice('T3N policy allowed the proposal to continue. ALLOW is not authorization or execution.');
  });

  const selectScenario = (scenario: EnterpriseScenarioDefinition) => {
    selectionGeneration.current += 1;
    setSelectedScenarioId(scenario.id);
    setIncidentScenarioId(null);
    setSelectedWorkspaceIncidentId(null);
    setIncidentDetailError(null);
    setIncidentDetailLoading(false);
    setPrompt(scenario.prompt);
    clearIncidentRuntime();
    setError(null);
    setNotice(`${scenario.title} loaded with synthetic demo data. No API call or authorization has occurred yet.`);
  };

  const askAgentForRemediation = () => run(async () => {
    if (!incident || !incidentScenario?.remediationPrompt) return;
    const generation = selectionGeneration.current;
    const result = await privacyGuardApi.analyzeAgentInIncident(incident.id, incidentScenario.remediationPrompt);
    if (!isCurrentSelection(generation)) {
      await Promise.all([refreshWorkspace(), refreshBusinessImpact()]);
      return;
    }
    setAgentAnalysis(result);
    setRemediationExecution(null);
    setIncident(result.incident);
    setSelectedAction(result.action);
    setDecision(result.decision);
    await Promise.all([refreshIncident(result.incident, result.action.id, generation), refreshBusinessImpact(), refreshWorkspace()]);
    if (!isCurrentSelection(generation)) return;

    if (result.decision.decision === 'DENY') {
      setNotice('The agent produced a new remediation proposal, but T3N denied it. No fallback action was created.');
    } else if (result.decision.decision === 'REDACT') {
      setNotice('The agent produced a new remediation proposal, but T3N requires further minimization. No fallback action was created.');
    } else if (result.action.action !== 'revoke-credential') {
      setNotice(`T3N allowed the agent proposal for ${result.action.action}, but protected execution in this demo exists only for revoke-credential. No fallback action was created.`);
    } else {
      setNotice('The agent proposed a credential revocation and T3N allowed it. Human authorization is still required before protected execution.');
    }
  });

  const retryEvaluation = () => run(async () => {
    if (!incident || !selectedAction) return;
    const generation = selectionGeneration.current;
    const result = await privacyGuardApi.evaluate(incident.id, selectedAction.id);
    if (isCurrentSelection(generation)) setDecision(result);
    await Promise.all([refreshIncident(incident, selectedAction.id, generation), refreshBusinessImpact(), refreshWorkspace()]);
  });

  const authorize = () => run(async () => {
    if (!incident || !selectedAction) return;
    const generation = selectionGeneration.current;
    await privacyGuardApi.authorizeRemediation(incident.id, selectedAction.id);
    await Promise.all([refreshIncident(incident, selectedAction.id, generation), refreshBusinessImpact(), refreshWorkspace()]);
    if (isCurrentSelection(generation)) setNotice('Human authorization recorded. Protected execution still requires the bound executor and one-time proof.');
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
    const generation = selectionGeneration.current;
    const result = await privacyGuardApi.executeRemediation(incident.id, selectedAction.id);
    if (isCurrentSelection(generation)) setRemediationExecution(result);
    await Promise.all([refreshIncident(incident, selectedAction.id, generation), refreshBusinessImpact(), refreshWorkspace()]);
    if (isCurrentSelection(generation)) setNotice(executionNotice(result));
  });

  const verifyExternalState = () => run(async () => {
    if (!incident || !selectedAction) return;
    const generation = selectionGeneration.current;
    const result = await privacyGuardApi.verifyRemediation(incident.id, selectedAction.id);
    if (isCurrentSelection(generation)) setRemediationExecution(result);
    await Promise.all([refreshIncident(incident, selectedAction.id, generation), refreshBusinessImpact(), refreshWorkspace()]);
    if (isCurrentSelection(generation)) setNotice(executionNotice(result));
  });

  const selectAction = (action: ActionProposal) => {
    const generation = selectionGeneration.current;
    setSelectedAction(action);
    setDecision(null);
    setRemediationExecution(null);
    setExecutionTrace([]);
    if (incident) void Promise.all([
      loadDecision(incident, action, generation),
      loadRemediation(incident, action, generation),
      loadExecutionTrace(incident, action, generation),
    ]);
  };

  const retrySelectedIncident = () => {
    const selected = workspace?.incidents.find((item) => item.id === selectedWorkspaceIncidentId);
    if (selected) void openWorkspaceIncident(selected);
  };

  const showSafePath = Boolean(incidentScenario?.remediationPrompt) && decision?.decision === 'DENY' && Boolean(incident);

  return (
    <>
      <DashboardTabs active={view} onChange={setView} />
      {error && <div className="feedback feedback-error" role="alert">{error}</div>}
      {notice && <div className="feedback feedback-success" role="status">{notice}</div>}

      {view === 'demo' && (
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
          <BusinessOutcomeSummary
            scenario={scenarioContext}
            incident={incident}
            selectedAction={selectedAction}
            decision={decision}
            remediationExecution={remediationExecution}
            agentAnalysis={agentAnalysis}
          />
          <ControlImpactSummary
            impact={businessImpact}
            loading={businessImpactLoading}
            error={businessImpactError}
            window={businessImpactWindow}
            onWindowChange={setBusinessImpactWindow}
          />
          <IncidentWorkspaceQueue
            workspace={workspace}
            selectedIncidentId={selectedWorkspaceIncidentId}
            loading={workspaceLoading}
            error={workspaceError}
            detailLoading={incidentDetailLoading}
            detailError={incidentDetailError}
            onSelect={(item) => void openWorkspaceIncident(item)}
            onRetry={() => { void refreshWorkspace(); }}
            onRetrySelected={retrySelectedIncident}
          />
          <main className="dashboard-grid">
            <div className="dashboard-main">
              <EnterpriseScenarioCatalog selectedId={selectedScenarioId} busy={busy} onSelect={selectScenario} />
              <AgentPromptPanel busy={busy} prompt={prompt} onPromptChange={setPrompt} onAnalyze={analyzeAgentPrompt} />
              <AgentProposalPanel analysis={agentAnalysis} />
              {!incidentDetailLoading && (!incident ? <EmptyState /> : <>
                <IncidentSummary incident={incident} />
                {showSafePath && <NextRequiredAction busy={busy} onAskAgent={() => void askAgentForRemediation()} />}
                <div className="two-column"><ActionProposalPanel actions={actions} selectedActionId={selectedAction?.id ?? null} onSelect={selectAction} /><DecisionPanel decision={decision} /></div>
                <RemediationPanel action={selectedAction} decision={decision} execution={remediationExecution} busy={busy} onAuthorize={authorize} onExecute={execute} onVerify={verifyExternalState} />
              </>)}
            </div>
            <aside className="dashboard-side" aria-label="Live activity"><ExecutionTrace events={executionTrace} action={selectedAction} /><AuditTrail events={history} /></aside>
          </main>
        </>
      )}

      {view === 'presentation' && (
        <ExecutiveDemoView
          scenario={scenarioContext}
          systemStatus={systemStatus}
          statusLoading={statusLoading}
          agentAnalysis={agentAnalysis}
          selectedAction={selectedAction}
          decision={decision}
          remediationExecution={remediationExecution}
          businessImpact={businessImpact}
          businessImpactLoading={businessImpactLoading}
          businessImpactError={businessImpactError}
          evidence={evidence}
          evidenceLoading={evidenceLoading}
          evidenceError={evidenceError}
          onOpenEvidence={() => setView('evidence')}
        />
      )}

      {view === 'evidence' && (
        <EvidenceCenter evidence={evidence} loading={evidenceLoading} error={evidenceError} onRefresh={() => void refreshEvidence()} />
      )}
    </>
  );
}
