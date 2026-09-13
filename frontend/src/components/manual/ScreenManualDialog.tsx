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
          <section>
            <h3>What this screen is for</h3>
            <p id="screen-manual-purpose">This dashboard demonstrates a simple enterprise rule: AI may propose an action, but it cannot authorize itself or declare a critical action complete. You can choose a safe enterprise scenario, inspect or edit its synthetic prompt, observe the real AI proposal and independent T3N policy decision, and use protected execution only where a matching executor and independent verifier actually exist.</p>
          </section>
          <section>
            <h3>How to read the trust flow</h3>
            <p><strong>AI proposal</strong> shows whether a structured action proposal is available. <strong>Policy</strong> returns DENY, REDACT or ALLOW. DENY blocks the proposal, REDACT requires minimization and ALLOW only permits the proposal to continue. <strong>ALLOW does not mean executed.</strong> Critical remediation still requires explicit human authorization and a supported executor. <strong>COMPLETED appears only after independent read-back verifies the expected external state.</strong></p>
          </section>
          <section>
            <h3>Views and filters</h3>
            <p><strong>Protection demo</strong> contains the enterprise scenario catalog, prompt, proposal, policy decision, supported human authorization and protected execution, incident retention, the technical Execution Trace and the separate Business Audit Trail. <strong>Proof &amp; evidence</strong> shows which testnet outcomes were actually observed. The scenario cards are demonstration presets, not policy filters or permissions. Technical T3N identifiers, contract and delegation details remain available under <strong>Show technical details</strong> without dominating the main flow.</p>
          </section>
          <section>
            <h3>Enterprise scenarios</h3>
            <p><strong>Credential compromised</strong> exercises <code>revoke-credential</code> and can demonstrate both adversarial denial and the complete protected revocation/read-back flow. <strong>Account takeover</strong> prepares <code>isolate-account</code>. <strong>Record security incident</strong> prepares <code>create-incident</code> without outbound network access. <strong>Notify security contact</strong> prepares <code>notify-security</code> using only the logical <code>verified_email</code> reference, never a plaintext email or raw T3N placeholder. The latter three are policy-evaluation demonstrations in the current build; the interface does not pretend that a verified completion executor exists for them.</p>
          </section>
          <section>
            <h3>Prompt field and actions</h3>
            <p>Selecting a scenario loads a synthetic prompt and clears the prior scenario result so evidence from one scenario is not presented as another. Selection itself does not call an API. The prompt accepts up to 4,000 characters and remains editable. Do not paste literal private values, credentials or secrets. <strong>Ask agent</strong> sends the current prompt to the configured provider; the resulting structured proposal, not the selected card, is what T3N evaluates.</p>
          </section>
          <section>
            <h3>Proposal and private-data boundary</h3>
            <p>The model may propose only the action, resource, purpose, optional host, field names and supported logical private-data references. It cannot choose trusted identities, policy decisions, approvals or execution proof. Private values remain outside the browser and model; supported logical references are resolved only inside the protected T3N execution boundary. Incident free text follows the separate minimization and retention rule below and is not claimed to be anonymous.</p>
          </section>
          <section>
            <h3>Incident storage and retention</h3>
            <p>Incident title, summary and source are normalized on the server before persistence. High-confidence email, valid CPF, credential/token, bearer token, JWT, private-key, password and payment-card candidates are rejected before the database write. Accepted operational text is capped to smaller local limits and remains potentially identifying data; minimization is not anonymization. Every incident receives a server-controlled <strong>expiresAt</strong> calculated from its creation time. The default retention is 7 days and configuration is limited to 1–30 days. Expired incidents stop being returned by incident APIs immediately, then a scheduled transactional purge hard-deletes execution-trace events, remediation executions, policy decisions, action proposals, audit events and the incident. Existing rows without an expiration are backfilled on startup from their original creation time.</p>
          </section>
          <section>
            <h3>T3N trust provenance</h3>
            <p><strong>Trust anchor VERIFIED</strong> means the official signed T3N manifest established the cluster trust boundary for the authenticated sessions. <strong>Rollback floor PERSISTED</strong> means the accepted trust-manifest version is stored as a monotonic high-water mark across gateway restarts. The displayed trust-manifest version is that observed high-water version. These states are not per-request hardware attestation. Trust-manifest unavailability, rollback rejection, corrupted persisted state or a missing version fail closed and must not appear as a green success state.</p>
          </section>
          <section>
            <h3>Execution trace</h3>
            <p><strong>Trace</strong> identifies one technical HTTP attempt; <strong>Request</strong> identifies the logical operation and remains stable for idempotency. The browser creates a fresh safe trace for each API attempt, the backend validates or replaces it, returns it in <strong>X-Trace-Id</strong>, and propagates the same trace through authenticated gateway calls. The selected action timeline can therefore contain multiple trace IDs for the same Request when the operator retries or advances the flow. Typical states are <strong>RECEIVED</strong>, <strong>SENT</strong>, <strong>ACCEPTED</strong>, <strong>AUTHORIZED</strong>, <strong>VERIFIED</strong>, <strong>DENIED</strong>, <strong>REDACTED</strong>, <strong>FAILED</strong> and <strong>UNAVAILABLE</strong>. The timeline contains only bounded identifiers, stage/state, timestamp, reason code and same-process duration when available. It never exposes raw request/response bodies, headers, capabilities, keys, passwords, private values or resolved T3N placeholders. A T3N request or receipt identifier is shown only if the platform actually returns one; the application does not invent one.</p>
          </section>
          <section>
            <h3>Decision states</h3>
            <p><strong>DENY</strong> blocks the proposal before protected egress. <strong>REDACT</strong> requires a smaller data scope before the action may continue. <strong>ALLOW</strong> means policy permits the proposal, but it is not human approval, execution or completion.</p>
          </section>
          <section>
            <h3>Human authorization and protected execution</h3>
            <p>The current complete executor/read-back contract is for <code>revoke-credential</code>. <strong>Authorize credential revocation</strong> records the human business decision for an allowed revocation. <strong>Execute protected credential revocation</strong> claims the approved action before sending the side effect and uses replay-resistant execution data. <strong>Verify external state</strong> performs an independent read-back and never sends the side effect again. Other scenario actions remain visible for genuine T3N policy evaluation without unsupported execution controls.</p>
          </section>
          <section>
            <h3>Execution and verification states</h3>
            <p><strong>EXECUTING</strong> means execution is in progress. <strong>PENDING_VERIFICATION</strong> means the external action was accepted but completion is not proven. <strong>COMPLETED</strong> requires independent verification of the expected state. <strong>UNVERIFIED</strong> means the result is ambiguous or does not match. <strong>FAILED</strong> means a known failure. An HTTP success response alone is never enough to display COMPLETED.</p>
          </section>
          <section>
            <h3>Retry rule</h3>
            <p>A retry keeps the same logical Request ID but receives a new Trace ID, so idempotency and observability stay independent. Repeating execution for an already claimed action reconciles persisted state instead of intentionally sending a second side effect. An ambiguous outcome remains UNVERIFIED and can be read back only when a verifiable operation ID exists.</p>
          </section>
          <section>
            <h3>Evidence states</h3>
            <p><strong>PASS</strong> is an observed result that matched the expected security outcome. <strong>FAIL</strong> is an observed mismatch. <strong>NOT RUN</strong> means the scenario was not executed and is never counted as proof.</p>
          </section>
          <section>
            <h3>Rules and permissions</h3>
            <p>Application sign-in does not grant T3N authority, and selecting an enterprise scenario grants nothing. Policy must allow the exact action and scope. Where protected execution is implemented, critical remediation additionally requires human authorization and runtime controls, and completion requires independent read-back. DENY and REDACT cannot be promoted to execution by the interface. A Trace ID is correlation metadata only; it grants no authority and cannot be used to access another incident or action. Incident retention is controlled by the server, not by browser input, and expired incident content cannot be retrieved through the incident API.</p>
          </section>
          <section>
            <h3>Main flow</h3>
            <p>1. Sign in. 2. Read the trust flow and confirm whether T3N controls are available. 3. Choose an enterprise scenario. 4. Review or edit the synthetic prompt without adding private values. 5. Select Ask agent. 6. Inspect the actual proposal. 7. Observe DENY, REDACT or ALLOW from T3N. 8. Inspect the current incident and its automatic expiration date. 9. If the actual action is credential revocation and ALLOW, optionally prepare the minimum revocation path and record human authorization. 10. Execute it once through the protected executor. 11. Treat acceptance as pending verification. 12. Verify the external state. 13. Review the Execution Trace, Business Audit Trail and Proof &amp; evidence. 14. Open technical details when contract, delegation or trust-provenance metadata is needed. Expired incident data is removed by the server retention process.</p>
          </section>
          <section>
            <h3>Messages and error states</h3>
            <p>Sensitive prompt content is rejected before reaching the external provider. Incident content containing a high-confidence sensitive literal is rejected with HTTP 422 before persistence and the response does not echo that literal. Provider, T3N or trust-boundary failures fail closed. Expired application sessions require sign-in again. Rate-limited sign-in follows the server retry interval. Switching scenarios clears prior scenario results. Unsupported actions show policy-evaluation-only guidance instead of execution controls. Ambiguous execution remains UNVERIFIED and is not automatically re-executed. Error messages and trace metadata must not expose private values, passwords, credentials, capabilities, request bodies or raw headers.</p>
          </section>
        </div>
      </section>
    </div>,
    document.body,
  ) : null;

  return (
    <>
      <button ref={triggerRef} type="button" className="button button-secondary manual-trigger" aria-label="Open Screen Manual" title="Manual da Tela / Screen Manual" onClick={() => setOpen(true)}>
        <BookOpen aria-hidden="true" /><span>Manual da Tela</span>
      </button>
      {dialog}
    </>
  );
}
