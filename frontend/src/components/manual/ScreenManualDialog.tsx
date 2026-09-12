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
              <section><h3>Purpose</h3><p id="screen-manual-purpose">Demonstrates that a real configured AI model can be manipulated by untrusted text but still cannot grant itself authority or retrieve private profile values. The model produces only a structured proposal with logical data references; the independent T3N TEE policy returns ALLOW, REDACT or DENY, and protected execution still requires explicit human authorization.</p></section>
              <section><h3>AI agent prompt</h3><p>The Prompt field accepts up to 4,000 characters and is treated as untrusted input. <strong>Load attack prompt</strong> fills a credential-exfiltration instruction. <strong>Load safe prompt</strong> fills a minimum legitimate remediation instruction. <strong>Ask agent</strong> sends the current prompt to the configured real provider. <strong>Run attack scenario</strong> sends the documented attack prompt directly through the same real provider path.</p></section>
              <section><h3>Agent proposal</h3><p>The model may provide only action, resource, purpose, optional host, requested field names and enumerated logical private references. For private contact data the supported reference is <strong>Verified email</strong>; the model never receives the email address itself. The server rejects unknown properties and attempts to provide decision, override, approval, DID, credentials, secrets, API keys or literal T3N placeholder strings.</p></section>
              <section><h3>Private data boundary</h3><p>A logical reference such as <strong>verified_email</strong> can be allowed only for the matching action and purpose. The Rust/WASM contract, not the model or browser, maps that reference to the supported T3N profile marker. T3N resolves the profile value only during protected egress. React, Java, gateway responses, audit records and evidence retain only non-sensitive metadata/reference names and never render the resolved plaintext.</p></section>
              <section><h3>Private data errors</h3><p>An unknown reference, a literal <code>{'{{profile...}}'}</code> marker supplied by a client, a reference unnecessary for the current action, missing profile data or missing user context fails closed or requires minimization. Placeholder errors identify only the category/problem and never include the private value.</p></section>
              <section><h3>Authority separation</h3><p>The AI provider never receives T3N tenant/agent keys, remediation credentials, service tokens, one-time remediation capabilities or resolved profile values. Agent DID comes from the authenticated T3N agent session, and tenant/data-owner DID comes from the authenticated tenant session. The model cannot choose either identity, the contract, a policy decision or the human authorization proof.</p></section>
              <section><h3>Operator session</h3><p>The application operator uses runtime-only application credentials. This session is separate from T3N tenant, agent and AI-provider identities. Signing out invalidates the application session.</p></section>
              <section><h3>Views</h3><p><strong>Demo</strong> contains AI prompt, agent proposal, logical private-data categories, incident, T3N decision, human authorization, remediation and business audit flow. <strong>Evidence</strong> is read-only and displays only a sanitized, internally consistent live T3N evidence bundle. Evidence refresh never invokes the model or testnet operations from the browser.</p></section>
              <section><h3>Live operational status</h3><p>Tenant and Agent are authenticated only when their T3N sessions are ready. Contract <strong>Resolved</strong> means canonical id/version were resolved; it is not hardware attestation. Delegation comes from the observed member grant and can be ACTIVE, REVOKED, NOT_GRANTED or UNKNOWN.</p></section>
              <section><h3>Decision states</h3><p><strong>DENY</strong> blocks the proposed action. <strong>REDACT</strong> means the proposal requests normal fields or private references outside the minimum allowed scope and must be minimized before continuing. <strong>ALLOW</strong> means policy accepts the proposal; it does not mean the action executed, that a profile value was resolved, or that human approval exists.</p></section>
              <section><h3>Remediation actions</h3><p><strong>Prepare safe remediation</strong> creates the known minimum structured remediation when a judge wants to continue after the attack. A legitimate AI prompt can also produce an ALLOW proposal through <strong>Ask agent</strong>. <strong>Authorize remediation</strong> records human business authorization only. <strong>Execute protected remediation</strong> creates a short-lived one-time proof bound to the exact persisted ALLOW action, including its logical private references, before the gateway can invoke the TEE contract.</p></section>
              <section><h3>Evidence states</h3><p><strong>PASS</strong> means the observed result matched expectation. <strong>FAIL</strong> means it did not. <strong>NOT RUN</strong> means the scenario was not executed and is never counted as PASS. Profile-placeholder behavior must remain NOT RUN in live evidence until a compatible testnet profile/user context actually executes it.</p></section>
              <section><h3>Rules and permissions</h3><p>Application authentication does not imply T3N authorization. The agent still needs active delegation for the exact contract function, scopes and outbound host. A DENY or REDACT cannot be human-authorized for remediation. Gateway privileged execution also requires internal service authentication and a matching, unexpired, unused authorization proof. Private references are enumerated and bound to action/purpose by policy.</p></section>
              <section><h3>Main flow</h3><p>1. Sign in. 2. Confirm tenant, agent, contract and delegation. 3. Run the attack prompt through the real AI provider. 4. Inspect the model's structured proposal and any logical private reference. 5. Observe independent T3N DENY/REDACT/ALLOW. 6. Load/submit a legitimate prompt or prepare the minimum safe action. 7. Record human authorization only after ALLOW. 8. Execute protected remediation when appropriate. 9. For a private-reference action, T3N resolves the profile field only at protected egress. 10. Verify Evidence and audit history without plaintext PII.</p></section>
              <section><h3>Messages and errors</h3><p>If the AI provider is disabled or unavailable, the application fails closed and does not create an ALLOW automatically. Invalid tool output is rejected before T3N evaluation. A 401 means session/internal authentication is missing; 403 means authorization/CSRF/capability does not allow an action; replay is rejected as conflict. Provider, T3N and placeholder errors never expose provider keys, system prompt internals, profile values or raw upstream responses.</p></section>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
