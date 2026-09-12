import { useEffect, useRef, useState } from 'react';
import { BookOpen, X } from 'lucide-react';

export function ScreenManualDialog() {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const close = () => { setOpen(false); requestAnimationFrame(() => triggerRef.current?.focus()); };
  useEffect(() => { if (open) closeButtonRef.current?.focus(); }, [open]);
  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event: KeyboardEvent) => { if (event.key === 'Escape') close(); };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open]);

  return (
    <>
      <button ref={triggerRef} type="button" className="button button-secondary manual-trigger" aria-label="Open Screen Manual" title="Manual da Tela / Screen Manual" onClick={() => setOpen(true)}>
        <BookOpen aria-hidden="true" /><span>Screen Manual</span>
      </button>
      {open && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && close()}>
          <section className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="screen-manual-title" aria-describedby="screen-manual-purpose">
            <div className="modal-header">
              <div><p className="eyebrow">Manual da Tela</p><h2 id="screen-manual-title">Incident Response Dashboard</h2></div>
              <button ref={closeButtonRef} type="button" className="icon-button" aria-label="Close Screen Manual" title="Close Screen Manual" onClick={close}><X aria-hidden="true" /></button>
            </div>
            <div className="manual-content">
              <section><h3>Purpose</h3><p id="screen-manual-purpose">Demonstrates how T3 Privacy Guard blocks an unsafe agent proposal while still allowing a minimum, human-authorized remediation without exposing the remediation credential to browser, Java or the agent.</p></section>
              <section><h3>Operator session</h3><p>The application operator uses runtime-only application credentials. This session is separate from T3N tenant and agent identities. T3N private keys are never used in the login form. Signing out invalidates the application session.</p></section>
              <section><h3>Views</h3><p><strong>Demo</strong> contains the incident, policy decision, human authorization, remediation and business audit flow. <strong>Evidence</strong> is read-only and displays only a sanitized, internally consistent live T3N evidence bundle. Evidence refresh only rereads files; it never runs testnet operations from the browser.</p></section>
              <section><h3>Live operational status</h3><p>Tenant and Agent are authenticated only when their T3N sessions are ready. Contract <strong>Resolved</strong> means canonical id/version were resolved; it is not hardware attestation. Delegation comes from the observed member grant and can be ACTIVE, REVOKED, NOT_GRANTED or UNKNOWN. Functions and hosts are shown only from that observed grant.</p></section>
              <section><h3>Evidence fields</h3><p>Evidence shows source, generation time, network, SDK version, canonical contract id/version, WASM SHA-256, tenant DID, agent DID and the allowlisted scenario results. The backend validates that manifest and testnet run agree on identity/version/hash before returning them.</p></section>
              <section><h3>Evidence states</h3><p><strong>PASS</strong>: the observed result matched the expected security outcome. <strong>FAIL</strong>: it did not match. <strong>NOT RUN</strong>: the scenario was not executed in the current evidence bundle and is never counted as PASS. If files are absent the screen says that no live T3N evidence has been generated yet. Invalid/inconsistent JSON is not rendered as proof.</p></section>
              <section><h3>Actions</h3><p><strong>Run attack scenario</strong> evaluates an exfiltration attempt. <strong>Prepare safe remediation</strong> evaluates the minimum legitimate revoke request. <strong>Authorize remediation</strong> records human business authorization but does not execute it. <strong>Execute protected remediation</strong> causes the backend to create a short-lived one-time authorization proof bound to the incident, action, persisted ALLOW decision and exact fields before the gateway can invoke the TEE contract. The proof never reaches the browser. <strong>Refresh status</strong> reloads operational state. <strong>Refresh evidence</strong> only rereads sanitized evidence. <strong>Sign out</strong> invalidates the operator session.</p></section>
              <section><h3>Rules and permissions</h3><p>Application authentication does not imply T3N authorization. The agent still needs an active delegation for the exact contract function, scopes and outbound host. A DENY or REDACT decision cannot be human-authorized for remediation. The gateway rejects protected execution without valid service authentication and a matching, unexpired, unused authorization proof. Reusing a consumed proof is rejected. UNKNOWN, NOT_GRANTED and REVOKED are never success states.</p></section>
              <section><h3>Main flow</h3><p>1. Sign in. 2. Confirm tenant, agent, contract and delegation separately. 3. Run attack and observe DENY. 4. Prepare safe action and observe ALLOW. 5. Record human authorization. 6. Execute protected remediation; the server binds that authorization to a one-time proof. 7. Open Evidence and verify T3N_TESTNET metadata/results. 8. Review audit history. 9. Sign out.</p></section>
              <section><h3>Messages and errors</h3><p>A 401 means the operator session or internal service authentication is missing/invalid. A 403 means the session, CSRF protection or one-time remediation proof does not allow the action. A replayed proof is rejected as a conflict. Missing evidence is an explicit empty state. Operational/evidence states that cannot be validated are never presented as verified or successful.</p></section>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
