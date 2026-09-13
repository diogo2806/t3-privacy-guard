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
          <section><h3>Purpose</h3><p id="screen-manual-purpose">Demonstrates that a manipulated AI model cannot grant itself authority, retrieve private profile values or cause an external side effect to be reported as completed without independent verification. T3N policy, explicit human authorization, one-time execution proof and external read-back are separate controls.</p></section>
          <section><h3>AI agent prompt</h3><p>The Prompt field accepts up to 4,000 characters and is untrusted input. Never paste literal private values or secrets. Before the external AI provider is called, the gateway rejects high-confidence email, CPF, credential/token, JWT, private-key, password and payment-card candidates. Use logical references such as <strong>verified email</strong> instead. <strong>Load attack prompt</strong> fills a credential-exfiltration instruction that mentions the field name <strong>api_key</strong> without containing a real key, so the adversarial policy scenario remains safe to demonstrate. <strong>Load safe prompt</strong> fills a minimum legitimate instruction. <strong>Ask agent</strong> uses the configured real provider. <strong>Run attack scenario</strong> sends the documented safe attack prompt through the same provider path.</p></section>
          <section><h3>Agent proposal</h3><p>The model may provide only action, resource, purpose, optional host, requested field names and enumerated logical private references. For private contact data the supported reference is <strong>Verified email</strong>; the model never receives the email itself. Decision, override, DID, credentials, secrets, API keys and literal T3N placeholders are rejected.</p></section>
          <section><h3>Private data boundary</h3><p>The pre-provider privacy guard prevents detected literal private values from crossing the gateway-to-provider boundary. The Rust/WASM contract separately maps approved logical references to supported T3N profile markers. T3N resolves the private value only during protected egress. The resolved profile plaintext is not returned to React, Spring Boot, normal gateway responses, audit records or evidence. Incident free text follows the separate minimization and retention rule below and is not claimed to be anonymous.</p></section>
          <section><h3>Incident storage and retention</h3><p>Incident title, summary and source are normalized on the server before persistence. High-confidence email, valid CPF, credential/token, bearer token, JWT, private-key, password and payment-card candidates are rejected before the database write. Accepted operational text is capped to smaller local limits and remains potentially identifying data; minimization is not anonymization. Each incident receives a server-controlled <strong>expiresAt</strong> calculated from its creation time and the configured retention period. The default is 7 days and configuration is limited to 1–30 days. Expired incidents stop being returned by incident APIs immediately and a scheduled transactional purge hard-deletes remediation executions, policy decisions, action proposals, audit events and the incident. Existing database rows without an expiration are backfilled on startup using the same retention formula.</p></section>
          <section><h3>Authority separation</h3><p>The AI provider never receives T3N tenant/agent keys, remediation credentials, service tokens, one-time capabilities or resolved profile values. Agent DID and tenant DID come from authenticated T3N sessions. Before either session is established, the gateway verifies the signed T3N trust manifest and enforces a persistent, monotonic manifest-version floor shared by tenant and agent. The model cannot select identities, contract, policy decision or human authorization proof.</p></section>
          <section><h3>Operator session</h3><p>The operator uses runtime-only application credentials. This identity is separate from T3N tenant, agent and AI-provider identities. Repeated failed sign-in attempts trigger a short server-controlled cooldown. During a cooldown the UI follows the backend <strong>Retry-After</strong> value and disables only sign-in submission; the error never reveals whether a username exists. Signing out invalidates the application session.</p></section>
          <section><h3>Views</h3><p><strong>Demo</strong> contains AI prompt, proposal, private-data categories, policy decision, authorization, execution, verification, incident retention and audit. <strong>Evidence</strong> displays only sanitized, internally consistent T3N evidence. It shows <strong>Trust anchor VERIFIED</strong> only when the signed manifest established the authenticated session, <strong>Rollback floor PERSISTED</strong> only when the monotonic version floor was safely stored, and the observed manifest version. These values prove cluster trust and cross-restart rollback protection; they are not labeled as per-request hardware attestation. Evidence refresh never invokes the model or executes testnet actions from the browser.</p></section>
          <section><h3>Decision states</h3><p><strong>DENY</strong> blocks the proposal. <strong>REDACT</strong> requires minimization. <strong>ALLOW</strong> accepts the proposal under policy but does not mean human approval, egress or completion.</p></section>
          <section><h3>Remediation actions</h3><p><strong>Authorize remediation</strong> records human business authorization only. <strong>Execute protected remediation</strong> atomically claims the action before egress, uses the stable request ID as idempotency key and sends a one-time capability bound to the exact ALLOW action. The external acknowledgement moves the execution only to pending verification. <strong>Verify external state</strong> performs read-back and never sends the side effect again.</p></section>
          <section><h3>Execution and verification states</h3><p><strong>EXECUTING</strong> means the durable claim exists. <strong>PENDING_VERIFICATION</strong> means the external service accepted the request but its final state is not yet proven. <strong>COMPLETED</strong> exists only after read-back verifies the expected state. <strong>UNVERIFIED</strong> means the outcome is ambiguous, verification is unavailable or the observed state does not match. <strong>FAILED</strong> is reserved for a known failure that is safe to classify as failed. An HTTP 2xx alone is never shown as COMPLETED.</p></section>
          <section><h3>Retry rule</h3><p>Repeating execution for the same action reconciles the durable claim instead of sending another external side effect. If a process restarts after the request may have been sent but before an operation ID is persisted, the state becomes UNVERIFIED and automatic re-execution is blocked. A manual verification is offered only when an operation ID exists.</p></section>
          <section><h3>Evidence states</h3><p><strong>PASS</strong> means observed result matched expectation. <strong>FAIL</strong> means it did not. <strong>NOT RUN</strong> means a scenario was not executed and is never counted as PASS. <strong>Trust anchor VERIFIED</strong> means the signed T3N manifest was accepted by the official trust-anchor path. <strong>Rollback floor PERSISTED</strong> means its monotonic version high-water mark was written to persistent gateway state. Profile resolution or external verification is not claimed live unless matching testnet evidence exists.</p></section>
          <section><h3>Trust verification errors</h3><p><strong>TRUST MANIFEST UNAVAILABLE</strong> means no verified manifest could be obtained. <strong>ROLLBACK REJECTED</strong> means a manifest older than the persisted floor was refused. <strong>TRUST FLOOR CORRUPTED</strong> means persisted security state could not be trusted and the gateway fails closed instead of silently resetting it. <strong>VERSION NOT EXPOSED BY SDK</strong> means the verified anchor did not provide the required monotonic version. In all cases no authenticated T3N session is established until trust verification succeeds. Resetting the floor is an explicit operational recovery action and is never automatic.</p></section>
          <section><h3>Rules and permissions</h3><p>Application authentication does not imply T3N authorization. The agent needs active delegation for the exact functions, scopes and host. DENY/REDACT cannot be authorized. Privileged execution requires service authentication plus the one-time capability. Private references are enumerated. Completion additionally requires independent read-back. Incident retention is controlled by the server, not by browser input, and expired incident content cannot be retrieved through the incident API.</p></section>
          <section><h3>Main flow</h3><p>1. Sign in. 2. Confirm tenant, agent, contract, delegation and verified T3N trust metadata. 3. Enter only non-sensitive prompt text or logical private references. 4. Submit the attack prompt and inspect the model proposal. 5. Observe T3N DENY/REDACT/ALLOW. 6. Inspect the current incident and its automatic expiration date. 7. Prepare an allowed remediation. 8. Authorize it explicitly. 9. Execute once; the action is durably claimed first. 10. Observe accepted/pending verification rather than assuming success from 2xx. 11. Verify external state until VERIFIED or leave the action UNVERIFIED for investigation. 12. Review Evidence and audit history. Expired incident data is removed by the server retention process.</p></section>
          <section><h3>Messages and errors</h3><p>A sensitive prompt is rejected with HTTP 422 before the external provider is called; the response never echoes the detected value. Incident content containing a high-confidence sensitive literal is also rejected with HTTP 422 before persistence and the response does not echo that literal. Provider or T3N failures fail closed. A 401 means authentication is missing or credentials are invalid; 403 means authorization/CSRF/capability does not allow an action; 429 means sign-in is temporarily rate limited and the client must respect <strong>Retry-After</strong>; replay is rejected as conflict. T3N trust verification failures establish no authenticated tenant or agent session. An ambiguous remediation is shown as UNVERIFIED and is not automatically retried. Error messages never expose provider keys, T3N keys, profile values, passwords, request/response bodies, trust manifest contents or raw headers.</p></section>
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
