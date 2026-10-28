import { FileClock, ListChecks, Plus, RefreshCw, RotateCcw, ShieldCheck, Trash2, Upload } from 'lucide-react';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  PrivacyGuardApiError,
  privacyGuardApi,
  type PolicyDocument,
  type PolicyHistoryEntry,
  type PolicyValidation,
  type PolicyView,
} from '../../services/privacyGuardApi';
import { Button } from '../ui/Button';
import { InlineNotice } from '../ui/InlineNotice';
import { SectionHeader } from '../ui/SectionHeader';
import { Surface } from '../ui/Surface';
import { diffPolicies, draftProblems, emptyDraftAction, fromDraft, toDraft, type DraftAction, type PolicyDraft } from './policyDraft';

interface Props {
  /** POLICY_ADMIN may publish and roll back; other roles that reach this tab (AUDITOR) only read. */
  canEdit: boolean;
  onSessionExpired: () => void;
}

function readOnlyReason(view: PolicyView, canEdit: boolean): string | null {
  if (!view.administrationConfigured) {
    return 'Policy administration is not configured. Set GUARD_RUNTIME_POLICY_ADMIN_TOKEN for a guard-runtime caller granted manage-policy to see and change the policy here.';
  }
  if (!view.managed) return 'guard-runtime keeps this policy as a read-only file. Set GUARD_RUNTIME_POLICY_DIR on guard-runtime to publish versions from here.';
  if (!canEdit) return 'Your role can read the policy. Publishing and rollback need the POLICY_ADMIN role.';
  return null;
}

function shortHash(hash?: string | null): string {
  return hash ? `${hash.slice(0, 12)}…` : 'not available';
}

function formatTime(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString();
}

const OPERATION_LABEL: Record<PolicyHistoryEntry['operation'], string> = { seed: 'Seeded from file', publish: 'Published', rollback: 'Rolled back' };

export function PolicyEditor({ canEdit, onSessionExpired }: Props) {
  const [view, setView] = useState<PolicyView | null>(null);
  const [history, setHistory] = useState<PolicyHistoryEntry[]>([]);
  const [draft, setDraft] = useState<PolicyDraft | null>(null);
  const [validation, setValidation] = useState<PolicyValidation | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const handleError = useCallback((cause: unknown, fallback: string) => {
    if (cause instanceof PrivacyGuardApiError && cause.status === 401) { onSessionExpired(); return; }
    setError(cause instanceof Error ? cause.message : fallback);
  }, [onSessionExpired]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const current = await privacyGuardApi.policy();
      setView(current);
      setDraft(current.document ? toDraft(current.document) : null);
      setValidation(null);
      setHistory(current.administrationConfigured && current.managed ? await privacyGuardApi.policyHistory() : []);
    } catch (cause) {
      handleError(cause, 'The policy could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [handleError]);

  useEffect(() => { void load(); }, [load]);

  const editable = Boolean(view && canEdit && view.administrationConfigured && view.managed && view.document);
  const candidate = useMemo<PolicyDocument | null>(() => (draft ? fromDraft(draft) : null), [draft]);
  const changes = useMemo(() => (view?.document && candidate ? diffPolicies(view.document, candidate) : []), [view, candidate]);
  const problems = draft ? draftProblems(draft) : [];

  const updateDraft = (next: PolicyDraft) => { setDraft(next); setValidation(null); setNotice(null); };
  const updateAction = (key: string, patch: Partial<DraftAction>) => {
    if (!draft) return;
    updateDraft({ ...draft, actions: draft.actions.map((action) => (action.key === key ? { ...action, ...patch } : action)) });
  };

  const validate = async () => {
    if (!candidate) return;
    setBusy(true);
    setError(null);
    try {
      setValidation(await privacyGuardApi.validatePolicy(candidate));
    } catch (cause) {
      handleError(cause, 'The policy could not be validated.');
    } finally {
      setBusy(false);
    }
  };

  const publish = async () => {
    if (!candidate || !view) return;
    setBusy(true);
    setError(null);
    try {
      const change = await privacyGuardApi.publishPolicy(candidate, view.hash ?? null);
      await load();
      setNotice(change.changed ? `Version ${change.version} is now the active policy.` : `Version ${change.version} was already active; nothing changed.`);
    } catch (cause) {
      handleError(cause, 'The policy could not be published.');
    } finally {
      setBusy(false);
    }
  };

  const rollback = async (version: string) => {
    if (!view) return;
    setBusy(true);
    setError(null);
    try {
      const change = await privacyGuardApi.rollbackPolicy(version, view.hash ?? null);
      await load();
      setNotice(`Version ${change.version} is active again.`);
    } catch (cause) {
      handleError(cause, 'The policy could not be rolled back.');
    } finally {
      setBusy(false);
    }
  };

  if (loading && !view) return <Surface aria-busy="true"><p className="card-copy">Loading policy…</p></Surface>;
  if (!view) {
    return (
      <Surface>
        {error && <div className="feedback feedback-error" role="alert">{error}</div>}
        <Button onClick={() => void load()}><RefreshCw aria-hidden="true" />Retry</Button>
      </Surface>
    );
  }

  const reason = readOnlyReason(view, canEdit);
  const rollbackTargets = new Set(history.map((entry) => entry.version));
  const seen = new Set<string>();

  return (
    <div className="policy-editor">
      {error && <div className="feedback feedback-error" role="alert">{error}</div>}
      {notice && <div className="feedback feedback-success" role="status">{notice}</div>}

      <Surface aria-labelledby="policy-current-title">
        <SectionHeader
          eyebrow="Enforced by guard-runtime"
          title="Active policy"
          titleId="policy-current-title"
          icon={<ShieldCheck aria-hidden="true" />}
          trailing={<Button className="audit-refresh" onClick={() => void load()} disabled={busy || loading}><RefreshCw aria-hidden="true" />Reload</Button>}
        />
        <dl className="policy-identity">
          <div><dt>Version</dt><dd><code>{view.version ?? 'none'}</code></dd></div>
          <div><dt>Hash</dt><dd><code title={view.hash ?? undefined}>{shortHash(view.hash)}</code></dd></div>
          <div><dt>State</dt><dd>{view.state}</dd></div>
        </dl>
        <p className="card-copy">
          Every decision records this version and hash, and an approval is bound to them: after a new version is published, remediations approved under
          the previous one must be evaluated and approved again. Secret fields, unknown private references and malformed hosts are refused by guard-runtime
          whatever the document says.
        </p>
        {view.state === 'INVALID' && view.reason && <InlineNotice>guard-runtime reports the stored policy as invalid: {view.reason}</InlineNotice>}
        {reason && <InlineNotice>{reason}</InlineNotice>}
      </Surface>

      {draft && (
        <Surface aria-labelledby="policy-rules-title">
          <SectionHeader eyebrow={editable ? 'Draft' : 'Read only'} title="Action rules" titleId="policy-rules-title" icon={<ListChecks aria-hidden="true" />} />
          {editable && (
            <div className="policy-version-row">
              <label className="agent-prompt-label" htmlFor="policy-version">New version</label>
              <input id="policy-version" className="policy-input" value={draft.version} maxLength={64} disabled={busy}
                onChange={(event) => updateDraft({ ...draft, version: event.target.value })} />
            </div>
          )}
          <div className="policy-action-list">
            {draft.actions.map((action) => (
              <fieldset key={action.key} className="policy-action" disabled={!editable || busy}>
                <legend>{action.name || 'New action'}</legend>
                <div className="policy-field-grid">
                  <label>Action name<input className="policy-input" value={action.name} maxLength={80} onChange={(event) => updateAction(action.key, { name: event.target.value })} /></label>
                  <label>Purpose<input className="policy-input" value={action.purpose} maxLength={80} onChange={(event) => updateAction(action.key, { purpose: event.target.value })} /></label>
                  <label>Allowed fields<textarea className="policy-input" rows={2} value={action.fields} onChange={(event) => updateAction(action.key, { fields: event.target.value })} /></label>
                  <label>Allowed destination hosts<textarea className="policy-input" rows={2} value={action.hosts} disabled={!action.requiresHost}
                    onChange={(event) => updateAction(action.key, { hosts: event.target.value })} /></label>
                </div>
                <div className="policy-flags">
                  <label><input type="checkbox" checked={action.requiresHost} onChange={(event) => updateAction(action.key, { requiresHost: event.target.checked })} />Sends data to a destination host</label>
                  <label><input type="checkbox" checked={action.requiresHumanAuthorization} onChange={(event) => updateAction(action.key, { requiresHumanAuthorization: event.target.checked })} />Requires human authorization</label>
                  <label><input type="checkbox" checked={action.verifiedEmail} onChange={(event) => updateAction(action.key, { verifiedEmail: event.target.checked })} />May use the verified email reference</label>
                </div>
                {editable && (
                  <Button variant="ghost" className="policy-remove" aria-label={`Remove action ${action.name || 'new action'}`}
                    onClick={() => updateDraft({ ...draft, actions: draft.actions.filter((candidateAction) => candidateAction.key !== action.key) })}>
                    <Trash2 aria-hidden="true" />Remove
                  </Button>
                )}
              </fieldset>
            ))}
          </div>
          {editable && (
            <>
              <p className="card-copy">Separate list values with commas or new lines. guard-runtime lowercases and sorts them.</p>
              <div className="agent-prompt-actions">
                <Button onClick={() => updateDraft({ ...draft, actions: [...draft.actions, emptyDraftAction()] })} disabled={busy}><Plus aria-hidden="true" />Add action</Button>
                <Button variant="ghost" onClick={() => view.document && updateDraft(toDraft(view.document))} disabled={busy}>Discard changes</Button>
              </div>

              <div className="policy-review" aria-live="polite">
                <h3>Changes against version {view.version}</h3>
                {changes.length === 0 ? <p className="card-copy">No rule changes yet.</p> : (
                  <ul className="policy-diff">
                    {changes.map((change) => (
                      <li key={change.action} className={`policy-diff-${change.kind}`}>
                        <strong>{change.action}</strong> {change.kind}
                        {change.details.length > 0 && <ul>{change.details.map((detail) => <li key={detail}>{detail}</li>)}</ul>}
                      </li>
                    ))}
                  </ul>
                )}
                {problems.map((problem) => <InlineNotice key={problem}>{problem}</InlineNotice>)}
                {validation && (validation.valid
                  ? <div className="feedback feedback-success" role="status">guard-runtime accepts version {validation.version} (hash {shortHash(validation.hash)}).</div>
                  : <div className="feedback feedback-error" role="alert">guard-runtime rejects this policy: {validation.reason}</div>)}
              </div>
              <div className="agent-prompt-actions">
                <Button onClick={() => void validate()} disabled={busy || problems.length > 0}><ShieldCheck aria-hidden="true" />Validate</Button>
                <Button variant="primary" onClick={() => void publish()} disabled={busy || problems.length > 0 || changes.length === 0}><Upload aria-hidden="true" />Publish version {draft.version.trim()}</Button>
              </div>
            </>
          )}
        </Surface>
      )}

      {view.administrationConfigured && view.managed && (
        <Surface aria-labelledby="policy-history-title">
          <SectionHeader eyebrow="Hash-chained in guard-runtime" title="Version history" titleId="policy-history-title" icon={<FileClock aria-hidden="true" />} />
          {history.length === 0 ? <p className="card-copy">No versions recorded yet.</p> : (
            <ol className="policy-history">
              {history.map((entry) => {
                const firstForVersion = !seen.has(entry.version);
                seen.add(entry.version);
                const canRollBack = editable && firstForVersion && entry.version !== view.version && rollbackTargets.has(entry.version);
                return (
                  <li key={entry.sequence}>
                    <div>
                      <strong>{OPERATION_LABEL[entry.operation] ?? entry.operation} <code>{entry.version}</code></strong>
                      <span>{formatTime(entry.timestamp)} · {entry.requestedBy ? `requested by ${entry.requestedBy}` : 'no requester recorded'} · caller {entry.caller}</span>
                    </div>
                    {canRollBack && (
                      <Button onClick={() => void rollback(entry.version)} disabled={busy} aria-label={`Roll back to version ${entry.version}`}>
                        <RotateCcw aria-hidden="true" />Roll back
                      </Button>
                    )}
                  </li>
                );
              })}
            </ol>
          )}
        </Surface>
      )}
    </div>
  );
}
