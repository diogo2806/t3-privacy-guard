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
              <section><h3>Purpose</h3><p id="screen-manual-purpose">Demonstrates that a real configured AI model can be manipulated by untrusted text but still cannot grant itself authority. The model produces only a structured action proposal; the independent T3N TEE policy returns ALLOW, REDACT or DENY, and protected remediation still requires explicit human authorization.</p></section>
              <section><h3>AI agent prompt</h3><p>The Prompt field accepts up to 4,000 characters and is treated as untrusted input. <strong>Load attack prompt</strong> fills a credential-exfiltration instruction. <strong>Load safe prompt</strong> fills a minimum legitimate remediation instruction. <strong>Ask agent</strong> sends the current prompt to the configured real provider. <strong>Run attack scenario</strong> sends the documented attack prompt directly through the same real provider path.</p></section>
              <section><h3>Agent proposal</h3><p>The model may provide only action, resource, purpose, optional host and requested field names. The server rejects unknown properties and attempts to provide decision, override, approval, DID, credential, secret, API key or other privileged fields. Provider and model names are shown for provenance, not as an authorization signal.</p></section>
              <section><h3>Authority separation</h3><p>The AI provider never receives T3N tenant/agent keys, remediation credentials, service tokens or one-time remediation capabilities. Agent DID comes from the authenticated T3N agent session, and tenant/data-owner DID comes from the authenticated tenant session. The model cannot choose either identity, the contract, a policy decision or the human authorization proof.</p></section>
              <section><h3>Operator session</h3><p>The application operator uses runtime-only application credentials. This session is separate from T3N tenant, agent and AI-provider identities. Signing out invalidates the application session.</p></section>
              <section><h3>Views</h3><p><strong>Demo</strong> contains AI prompt, agent proposal, incident, T3N decision, human authorization, remediation and business audit flow. <strong>Evidence</strong> is read-only and displays only a sanitized, internally consistent live T3N evidence bundle. Evidence refresh never invokes the model or testnet operations from the browser.</p></section>
              <section><h3>Live operational status</h3><p>Tenant and Agent are authenticated only when their T3N sessions are ready. Contract <strong>Resolved</strong> means canonical id/version were resolved; it is not hardware attestation. Delegation comes from the observed member grant and can be ACTIVE, REVOKED, NOT_GRANTED or UNKNOWN.</p></section>
              <section><h3>Decision states</h3><p><strong>DENY</strong> blocks the proposed action. <strong>REDACT</strong> means the proposal requests data outside the minimum allowed scope and must be minimized before continuing. <strong>ALLOW</strong> means policy accepts the proposal; it does not mean the action executed or received human approval.</p></section>
              <section><h3>Remediation actions</h3><p><strong>Prepare safe remediation</strong> creates the known minimum structured remediation when a judge wants to continue after the attack. A legitimate AI prompt can also produce an ALLOW proposal through <strong>Ask agent</strong>. <strong>Authorize remediation</strong> records human business authorization only. <strong>Execute protected remediation</strong> causes the backend to create a short-lived one-time proof bound to the exact persisted ALLOW action before the gateway can invoke the TEE contract.</p></section>
              <section><h3>Evidence states</h3><p><strong>PASS</strong> means observed result matched expectation. <strong>FAIL</strong> means it did not. <strong>NOT RUN</strong> means the scenario was not executed and is never counted as PASS. A local fixture or unavailable AI provider is never presented as live AI proof.</p></section>
              <section><h3>Rules and permissions</h3><p>Application authentication does not imply T3N authorization. The agent still needs active delegation for the exact contract function, scopes and outbound host. A DENY or REDACT cannot be human-authorized for remediation. Gateway privileged execution also requires internal service authentication and a matching, unexpired, unused authorization proof.</p></section>
              <section><h3>Main flow</h3><p>1. Sign in. 2. Confirm tenant, agent, contract and delegation. 3. Run the attack prompt through the real AI provider. 4. Inspect the model's structured proposal. 5. Observe independent T3N DENY. 6. Load/submit a legitimate prompt or prepare the minimum safe action. 7. Observe ALLOW. 8. Record human authorization. 9. Execute protected remediation when appropriate. 10. Verify Evidence and audit history.</p></section>
              <section><h3>Messages and errors</h3><p>If the AI provider is disabled or unavailable, the application fails closed and does not create an ALLOW automatically. Invalid tool output is rejected before T3N evaluation. A 401 means session/internal authentication is missing; 403 means authorization/CSRF/capability does not allow an action; replay is rejected as conflict. Provider errors never expose provider keys, system prompt internals or raw upstream responses.</p></section>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
