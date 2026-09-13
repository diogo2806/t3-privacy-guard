import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { BookOpen, X } from 'lucide-react';

const FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',');

function focusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter((element) => {
    if (element.hidden || element.getAttribute('aria-hidden') === 'true' || element.closest('[hidden], [aria-hidden="true"]')) return false;
    const style = window.getComputedStyle(element);
    return style.display !== 'none' && style.visibility !== 'hidden';
  });
}

export function ScreenManualDialog() {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const close = () => { setOpen(false); requestAnimationFrame(() => triggerRef.current?.focus()); };

  useEffect(() => {
    if (!open) return undefined;

    const appRoot = document.getElementById('root');
    const previousAriaHidden = appRoot?.getAttribute('aria-hidden');
    appRoot?.setAttribute('inert', '');
    appRoot?.setAttribute('aria-hidden', 'true');
    closeButtonRef.current?.focus();

    const keepFocusInside = () => {
      const dialog = dialogRef.current;
      if (!dialog) return;
      const focusable = focusableElements(dialog);
      (focusable[0] ?? dialog).focus();
    };

    const onFocusIn = (event: FocusEvent) => {
      const dialog = dialogRef.current;
      if (dialog && event.target instanceof Node && !dialog.contains(event.target)) keepFocusInside();
    };

    const onKeyDown = (event: KeyboardEvent) => {
      const dialog = dialogRef.current;
      if (!dialog) return;
      if (event.key === 'Escape') {
        event.preventDefault();
        close();
        return;
      }
      if (event.key !== 'Tab') return;

      const focusable = focusableElements(dialog);
      if (focusable.length === 0) {
        event.preventDefault();
        dialog.focus();
        return;
      }

      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (focusable.length === 1 || !dialog.contains(active) || (event.shiftKey && active === first) || (!event.shiftKey && active === last)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      }
    };

    document.addEventListener('focusin', onFocusIn);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('focusin', onFocusIn);
      document.removeEventListener('keydown', onKeyDown);
      appRoot?.removeAttribute('inert');
      if (previousAriaHidden === null) appRoot?.removeAttribute('aria-hidden');
      else appRoot?.setAttribute('aria-hidden', previousAriaHidden);
    };
  }, [open]);

  const dialog = open ? createPortal(
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && close()}>
      <section ref={dialogRef} tabIndex={-1} className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="screen-manual-title" aria-describedby="screen-manual-purpose">
        <div className="modal-header">
          <div><p className="eyebrow">Manual da Tela</p><h2 id="screen-manual-title">Incident Response Dashboard</h2></div>
          <button ref={closeButtonRef} type="button" className="icon-button" aria-label="Close Screen Manual" title="Close Screen Manual" onClick={close}><X aria-hidden="true" /></button>
        </div>
        <div className="manual-content">
          <section><h3>Purpose</h3><p id="screen-manual-purpose">Demonstrates that one trust runtime can evaluate different enterprise security tasks while a manipulated AI model remains untrusted. Scenario presets prepare synthetic demonstration content only; the T3N Rust/WASM policy remains the authority for action, purpose, fields, private references and outbound destination.</p></section>
          <section><h3>Enterprise scenarios</h3><p><strong>Credential compromised</strong> targets <code>revoke-credential</code> and is the only current scenario with protected execution plus independent <code>REVOKED</code> read-back. <strong>Account takeover</strong> targets <code>isolate-account</code>. <strong>Record security incident</strong> targets <code>create-incident</code> and should not request an outbound host. <strong>Notify security contact</strong> targets <code>notify-security</code> and may request only the logical private reference <code>verified_email</code>. The latter three currently demonstrate real proposal and policy evaluation only; the interface does not invent an executor that is not implemented.</p></section>
          <section><h3>Scenario selection</h3><p>Selecting a scenario changes only presentation metadata and the editable synthetic prompt. It does not call the AI provider, grant permission, choose a DID, precompute ALLOW/DENY/REDACT or bypass T3N. Changing scenarios clears the previous result so an old proposal or policy decision cannot appear to belong to the newly selected task.</p></section>
          <section><h3>AI agent prompt</h3><p>The Prompt field accepts up to 4,000 characters and remains editable after a scenario is selected. <strong>Reload scenario prompt</strong> restores the selected synthetic preset without submitting it. <strong>Ask agent</strong> sends the current text through the configured real provider. The credential scenario additionally exposes <strong>Load credential attack prompt</strong> and <strong>Run credential attack</strong>; that adversarial prompt names the forbidden field <strong>api_key</strong> but contains no real secret. Never paste literal private values or secrets.</p></section>
          <section><h3>Agent proposal</h3><p>The model may provide only action, resource, purpose, optional host, requested field names and enumerated logical private references. The UI always shows the action the model actually proposed, even when it differs from the selected scenario. A divergent proposal is not rewritten to make a demo succeed; T3N evaluates it normally.</p></section>
          <section><h3>Private data boundary</h3><p>Before the external AI provider is called, the gateway rejects high-confidence email, CPF, credential/token, JWT, private-key, password and payment-card candidates. For private contact data the supported client-side category is <code>verified_email</code>, never a plaintext address and never a raw T3N profile placeholder. The Rust/WASM contract maps an approved logical reference to the supported T3N marker only inside the protected boundary.</p></section>
          <section><h3>Authority separation</h3><p>The AI provider never receives T3N tenant/agent keys, remediation credentials, service tokens, one-time capabilities or resolved profile values. Agent DID and tenant DID come from authenticated T3N sessions. Scenario presets cannot select identities, contract, policy decision, authorization proof or capability. Before either T3N session is established, the gateway verifies the signed T3N trust manifest and enforces a persistent, monotonic manifest-version floor shared by tenant and agent.</p></section>
          <section><h3>Operator session</h3><p>The operator uses runtime-only application credentials. This identity is separate from T3N tenant, agent and AI-provider identities. Repeated failed sign-in attempts trigger a short server-controlled cooldown. During a cooldown the UI follows the backend <strong>Retry-After</strong> value and disables only sign-in submission; the error never reveals whether a username exists. Signing out invalidates the application session.</p></section>
          <section><h3>Views</h3><p><strong>Demo</strong> contains scenario choice, editable AI prompt, actual proposal, policy decision, supported execution controls and audit. <strong>Evidence</strong> displays only sanitized, internally consistent T3N evidence. It shows <strong>Trust anchor VERIFIED</strong> only when the signed manifest established the authenticated session, <strong>Rollback floor PERSISTED</strong> only when the monotonic version floor was safely stored, and the observed manifest version. These values prove cluster trust and cross-restart rollback protection; they are not labeled as per-request hardware attestation. Evidence refresh never invokes the model or executes testnet actions from the browser.</p></section>
          <section><h3>Decision states</h3><p><strong>DENY</strong> blocks the proposal. <strong>REDACT</strong> requires minimization. <strong>ALLOW</strong> accepts the exact proposal under policy but does not mean human approval, outbound execution or completion. Scenario selection never changes these meanings.</p></section>
          <section><h3>Execution boundary</h3><p>Protected remediation controls are shown only when the selected credential scenario and the actual proposal are both <code>revoke-credential</code>. <strong>Prepare credential revocation</strong> creates the minimum structured revocation action and evaluates it through T3N. For <code>isolate-account</code>, <code>create-incident</code>, <code>notify-security</code> or a model proposal that diverges from the credential preset, the screen explicitly reports <strong>Policy evaluation only</strong>.</p></section>
          <section><h3>Credential remediation actions</h3><p><strong>Authorize remediation</strong> records human business authorization only. <strong>Execute protected remediation</strong> atomically claims the action before egress, uses the stable request ID as idempotency key and sends a one-time capability bound to the exact ALLOW action. The external acknowledgement moves execution only to pending verification. <strong>Verify external state</strong> performs read-back and never sends the side effect again.</p></section>
          <section><h3>Execution and verification states</h3><p><strong>EXECUTING</strong> means the durable claim exists. <strong>PENDING_VERIFICATION</strong> means the external service accepted the request but final state is not yet proven. <strong>COMPLETED</strong> exists only after read-back verifies the expected state. <strong>UNVERIFIED</strong> means the outcome is ambiguous, verification is unavailable or observed state does not match. <strong>FAILED</strong> is reserved for a known failure that is safe to classify as failed. An HTTP 2xx alone is never shown as COMPLETED.</p></section>
          <section><h3>Retry rule</h3><p>Repeating credential execution for the same action reconciles the durable claim instead of sending another external side effect. If a process restarts after the request may have been sent but before an operation ID is persisted, state becomes UNVERIFIED and automatic re-execution is blocked. Manual verification is offered only when an operation ID exists.</p></section>
          <section><h3>Evidence states</h3><p><strong>PASS</strong> means observed result matched expectation. <strong>FAIL</strong> means it did not. <strong>NOT RUN</strong> means a scenario was not executed and is never counted as PASS. <strong>Trust anchor VERIFIED</strong> means the signed T3N manifest was accepted by the official trust-anchor path. <strong>Rollback floor PERSISTED</strong> means its monotonic version high-water mark was written to persistent gateway state. Profile resolution or external verification is not claimed live unless matching testnet evidence exists.</p></section>
          <section><h3>Trust verification errors</h3><p><strong>TRUST MANIFEST UNAVAILABLE</strong> means no verified manifest could be obtained. <strong>ROLLBACK REJECTED</strong> means a manifest older than the persisted floor was refused. <strong>TRUST FLOOR CORRUPTED</strong> means persisted security state could not be trusted and the gateway fails closed instead of silently resetting it. <strong>VERSION NOT EXPOSED BY SDK</strong> means the verified anchor did not provide the required monotonic version. In all cases no authenticated T3N session is established until trust verification succeeds. Resetting the floor is an explicit operational recovery action and is never automatic.</p></section>
          <section><h3>Rules and permissions</h3><p>Application authentication does not imply T3N authorization. The agent needs active delegation for the exact functions, scopes and host. DENY/REDACT cannot be authorized. Privileged execution requires a supported executor, service authentication and the one-time capability. Private references are enumerated. Credential completion additionally requires independent read-back.</p></section>
          <section><h3>Main flow</h3><p>1. Sign in. 2. Confirm tenant, agent, contract, delegation and verified T3N trust metadata. 3. Choose a business scenario. 4. Review or edit only non-sensitive synthetic prompt text. 5. Ask the real agent. 6. Inspect the action it actually proposed. 7. Observe the real T3N DENY/REDACT/ALLOW decision. 8. For policy-only scenarios, stop at evaluation and audit. 9. For credential revocation, prepare the minimum action, authorize it explicitly, execute once and require independent read-back before COMPLETED. 10. Review Evidence and audit history.</p></section>
          <section><h3>Messages and errors</h3><p>A sensitive prompt is rejected with HTTP 422 before the external provider is called; the response never echoes the detected value. Provider or T3N failures fail closed. A scenario change reports that prior results were cleared. A model action that differs from the preset remains visible. A 401 means authentication is missing or credentials are invalid; 403 means authorization/CSRF/capability does not allow an action; 429 means sign-in is temporarily rate limited and the client must respect <strong>Retry-After</strong>; replay is rejected as conflict. T3N trust verification failures establish no authenticated tenant or agent session. Error messages never expose provider keys, T3N keys, profile values, passwords, request/response bodies, trust manifest contents or raw headers.</p></section>
        </div>
      </section>
    </div>,
    document.body,
  ) : null;

  return (
    <>
      <button ref={triggerRef} type="button" className="button button-secondary manual-trigger" aria-label="Open Screen Manual" title="Manual da Tela / Screen Manual" onClick={() => setOpen(true)}>
        <BookOpen aria-hidden="true" /><span>Screen Manual</span>
      </button>
      {dialog}
    </>
  );
}
