import { useCallback, useEffect, useState } from 'react';
import { ArrowRight, RotateCcw, ShieldCheck } from 'lucide-react';
import {
  PrivacyGuardApiError,
  privacyGuardApi,
  type ActionProposal,
  type AuditEvent,
  type Incident,
  type OperatorSession,
  type PolicyDecision,
  type SystemStatus,
} from '../../services/privacyGuardApi';
import { ActionProposalPanel } from '../actions/ActionProposalPanel';
import { OperatorSessionGate } from '../auth/OperatorSessionGate';
import { AuditTrail } from '../audit/AuditTrail';
import { IncidentSummary } from '../incidents/IncidentSummary';
import { AppHeader } from '../layout/AppHeader';
import { DecisionPanel } from '../policy/DecisionPanel';
import { RemediationPanel } from '../remediation/RemediationPanel';
import { EmptyState } from '../states/EmptyState';
import { SystemStatusBar } from '../status/SystemStatusBar';

function requestId(prefix: string) { return `${prefix}-${crypto.randomUUID()}`; }

export function PrivacyGuardDashboard() {
  const [session, setSession] = useState<OperatorSession | null>(null);
  const [sessionLoading, setSessionLoading] = useState(true);
  const [authBusy, setAuthBusy] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);

  useEffect(() => {
    void privacyGuardApi.session()
      .then(setSession)
      .catch(() => setSession({ authenticated: false }))
      .finally(() => setSessionLoading(false));
  }, []);

  const login = async (credentials: { username: string; password: string }) => {
    setAuthBusy(true);
    setAuthError(null);
    try {
      setSession(await privacyGuardApi.login(credentials));
    } catch (cause) {
      setSession({ authenticated: false });
      setAuthError(cause instanceof Error ? cause.message : 'Unable to sign in.');
    } finally {
      setAuthBusy(false);
    }
  };

  const logout = async () => {
    setAuthBusy(true);
    setAuthError(null);
    try {
      await privacyGuardApi.logout();
      setSession({ authenticated: false });
    } catch (cause) {
      setAuthError(cause instanceof Error ? cause.message : 'Unable to sign out safely.');
    } finally {
      setAuthBusy(false);
    }
  };

  const expireSession = useCallback(() => {
    setSession({ authenticated: false });
    setAuthError('Your operator session has expired. Sign in again to continue.');
  }, []);

  return (
    <div className="app-shell">
      <AppHeader />
      <OperatorSessionGate
        session={session}
        loading={sessionLoading}
        busy={authBusy}
        error={authError}
        onLogin={login}
        onLogout={logout}
      />
      {session?.authenticated && <AuthenticatedDashboard onSessionExpired={expireSession} />}
    </div>
  );
}

function AuthenticatedDashboard({ onSessionExpired }: { onSessionExpired: () => void }) {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [actions, setActions] = useState<ActionProposal[]>([]);
  const [selectedAction, setSelectedAction] = useState<ActionProposal | null>(null);
  const [decision, setDecision] = useState<PolicyDecision | null>(null);
  const [history, setHistory] = useState<AuditEvent[]>([]);
  const [statusLoading, setStatusLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleError = useCallback((cause: unknown, fallback: string) => {
    if (cause instanceof PrivacyGuardApiError && cause.status === 401) {
      onSessionExpired();
      return;
    }
    setError(cause instanceof Error ? cause.message : fallback);
  }, [onSessionExpired]);

  const refreshSystem = useCallback(async () => {
    setStatusLoading(true);
    try {
      setSystemStatus(await privacyGuardApi.systemStatus());
    } catch (cause) {
      setSystemStatus(null);
      handleError(cause, 'Unable to load system status.');
    } finally {
      setStatusLoading(false);
    }
  }, [handleError]);

  const loadDecision = useCallback(async (currentIncident: Incident, action: ActionProposal) => {
    if (action.status === 'PENDING') { setDecision(null); return; }
    try { setDecision(await privacyGuardApi.getDecision(currentIncident.id, action.id)); }
    catch (cause) {
      if (cause instanceof PrivacyGuardApiError && cause.status === 401) onSessionExpired();
      else setDecision(null);
    }
  }, [onSessionExpired]);

  const refreshIncident = useCallback(async (currentIncident: Incident, preferredActionId?: string) => {
    const [currentActions, currentHistory] = await Promise.all([
      privacyGuardApi.listActions(currentIncident.id),
      privacyGuardApi.history(currentIncident.id),
    ]);
    setActions(currentActions);
    setHistory(currentHistory);
    const selected = currentActions.find((item) => item.id === preferredActionId) ?? currentActions.at(-1) ?? null;
    setSelectedAction(selected);
    if (selected) await loadDecision(currentIncident, selected); else setDecision(null);
  }, [loadDecision]);

  useEffect(() => {
    void refreshSystem();
    void privacyGuardApi.listIncidents().then(async (items) => {
      const current = items[0] ?? null;
      setIncident(current);
      if (current) await refreshIncident(current);
    }).catch((cause) => handleError(cause, 'Unable to load incidents.'));
  }, [handleError, refreshIncident, refreshSystem]);

  const run = async (operation: () => Promise<void>) => {
    setBusy(true); setError(null); setNotice(null);
    try { await operation(); }
    catch (cause) { handleError(cause, 'The operation could not be completed safely.'); }
    finally { setBusy(false); }
  };

  const runAttackScenario = () => run(async () => {
    const current = await privacyGuardApi.createIncident({
      title: 'Credential exfiltration attempt',
      severity: 'CRITICAL',
      summary: 'Untrusted content instructed the AI agent to send a protected credential to an undelegated external host.',
      source: 'Adversarial demo',
    });
    setIncident(current);
    const attack = await privacyGuardApi.createAction(current.id, {
      requestId: requestId('attack'),
      action: 'revoke-credential',
      resource: 'credential:production-security-api',
      purpose: 'incident-remediation',
      host: 'attacker.example',
      fields: ['incident_id', 'credential_id', 'reason', 'api_key'],
    });
    setSelectedAction(attack);
    const result = await privacyGuardApi.evaluate(current.id, attack.id);
    setDecision(result);
    await refreshIncident(current, attack.id);
    setNotice(result.decision === 'DENY' ? 'Attack blocked by the T3N policy contract.' : `Unexpected ${result.decision} decision. Review policy and evidence.`);
  });

  const prepareSafeRemediation = () => run(async () => {
    if (!incident) return;
    const safeAction = await privacyGuardApi.createAction(incident.id, {
      requestId: requestId('remediation'),
      action: 'revoke-credential',
      resource: 'credential:production-security-api',
      purpose: 'incident-remediation',
      host: 'postman-echo.com',
      fields: ['incident_id', 'credential_id', 'reason'],
    });
    const result = await privacyGuardApi.evaluate(incident.id, safeAction.id);
    await refreshIncident(incident, safeAction.id);
    setDecision(result);
    setNotice(result.decision === 'ALLOW' ? 'Minimum remediation request allowed. Human authorization is still required before execution.' : `Remediation received ${result.decision}; execution remains blocked.`);
  });

  const retryEvaluation = () => run(async () => {
    if (!incident || !selectedAction) return;
    const result = await privacyGuardApi.evaluate(incident.id, selectedAction.id);
    setDecision(result);
    await refreshIncident(incident, selectedAction.id);
    setNotice(`Policy evaluation completed with ${result.decision}.`);
  });

  const selectAction = async (action: ActionProposal) => {
    setSelectedAction(action); setError(null); setNotice(null);
    if (incident) await loadDecision(incident, action);
  };

  const authorize = () => run(async () => {
    if (!incident || !selectedAction) return;
    await privacyGuardApi.authorizeRemediation(incident.id, selectedAction.id);
    await refreshIncident(incident, selectedAction.id);
    setNotice('Human authorization recorded. Protected TEE execution is now available for this allowed action.');
  });

  const execute = () => run(async () => {
    if (!incident || !selectedAction) return;
    const result = await privacyGuardApi.executeRemediation(incident.id, selectedAction.id);
    await refreshIncident(incident, selectedAction.id);
    setNotice(`Protected remediation completed with sanitized HTTP status ${result.httpCode}.`);
  });

  return (
    <>
      <SystemStatusBar status={systemStatus} loading={statusLoading} onRefresh={() => void refreshSystem()} />
      {error && <div className="feedback feedback-error" role="alert">{error}</div>}
      {notice && <div className="feedback feedback-success" role="status">{notice}</div>}

      {!incident ? <EmptyState onRun={runAttackScenario} busy={busy} /> : (
        <main className="dashboard-grid">
          <div className="dashboard-main">
            <IncidentSummary incident={incident} />
            <div className="scenario-actions">
              <button type="button" className="button button-danger" onClick={runAttackScenario} disabled={busy}><RotateCcw aria-hidden="true" />Run new attack scenario</button>
              <button type="button" className="button button-primary" onClick={prepareSafeRemediation} disabled={busy}><ShieldCheck aria-hidden="true" />Prepare safe remediation<ArrowRight aria-hidden="true" /></button>
              {selectedAction?.status === 'PENDING' && <button type="button" className="button button-secondary" onClick={retryEvaluation} disabled={busy}>Retry T3N evaluation</button>}
            </div>
            <div className="two-column">
              <ActionProposalPanel actions={actions} selectedActionId={selectedAction?.id ?? null} onSelect={(action) => void selectAction(action)} />
              <DecisionPanel decision={decision} />
            </div>
            <RemediationPanel action={selectedAction} decision={decision} busy={busy} onAuthorize={authorize} onExecute={execute} />
          </div>
          <aside className="dashboard-side"><AuditTrail events={history} /></aside>
        </main>
      )}
    </>
  );
}
