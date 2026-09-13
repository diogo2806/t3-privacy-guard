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
            <p id="screen-manual-purpose">This dashboard demonstrates a simple enterprise rule: AI may propose an action, but it cannot authorize itself, rewrite the active operational policy, retrieve protected profile values directly or declare a critical action complete. You can test an adversarial or legitimate prompt, inspect the independent policy decision and its exact policy provenance, authorize an allowed remediation as a human operator, execute it through T3N and verify the external result independently.</p>
          </section>
          <section>
            <h3>How to read the trust flow</h3>
            <p><strong>AI proposal</strong> shows whether a structured action proposal is available. <strong>Policy</strong> returns DENY, REDACT or ALLOW under an exact version/hash. DENY blocks the proposal, REDACT requires minimization and ALLOW only permits the proposal to continue. <strong>ALLOW does not mean executed.</strong> Critical remediation still requires explicit human authorization. <strong>COMPLETED appears only after independent read-back verifies the expected external state.</strong></p>
          </section>
          <section>
            <h3>Views and filters</h3>
            <p><strong>Protection demo</strong> contains the prompt, proposal, policy decision, policy provenance, human authorization, protected execution, verification, incident retention, the technical Execution Trace and the separate Business Audit Trail. <strong>Proof &amp; evidence</strong> shows which testnet outcomes were actually observed. The screen has no business-data filters; these two views organize the journey. Technical T3N identifiers, contract, policy, delegation and trust-provenance details remain available under <strong>Show technical details</strong> without dominating the main flow.</p>
          </section>
          <section>
            <h3>Prompt field and actions</h3>
            <p>The prompt is untrusted input and accepts up to 4,000 characters. Do not paste literal private values, credentials or secrets. <strong>Load attack prompt</strong> prepares a safe adversarial instruction without real sensitive values. <strong>Load safe prompt</strong> prepares a legitimate minimum-scope instruction. <strong>Ask agent</strong> sends the prompt to the configured provider. <strong>Run attack scenario</strong> executes the documented adversarial demo through the same provider path.</p>
          </section>
          <section>
            <h3>Proposal and private-data boundary</h3>
            <p>The model may propose only the action, resource, purpose, optional host, field names and supported logical private-data references. It cannot choose trusted identities, policy decisions, approvals, policy documents or execution proof. Resolved profile plaintext remains outside React, Spring Boot, normal gateway responses, audit records and evidence; supported logical references are resolved only inside the protected T3N execution boundary. Incident free text follows the separate minimization and retention rule below and is not claimed to be anonymous.</p>
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
            <p><strong>DENY</strong> blocks the proposal before protected egress. <strong>REDACT</strong> requires a smaller data scope before the action may continue. <strong>ALLOW</strong> means the active policy permits the proposal, but it is not human approval, execution or completion.</p>
          </section>
          <section>
            <h3>Policy version and hash</h3>
            <p><strong>Policy version</strong> identifies the operational rule set loaded by Rust/WASM from the private T3N KV map. <strong>Policy hash</strong> is the deterministic SHA-256 of the canonical policy document used for the decision. They provide policy provenance, not hardware attestation. A protected remediation is bound to those exact values; if the active policy changes after authorization, execution is rejected and the action must be evaluated again.</p>
          </section>
          <section>
            <h3>What policy can change</h3>
            <p>The versioned policy may enable actions and configure purpose, allowed hosts, allowed normal field names, supported logical private references, host requirement and whether human authorization is required. Critical invariants stay compiled in WASM: schema and size limits, fail-closed behavior, T3N identity boundaries, forbidden secret classes, private-reference vocabulary and safe host validation. A KV policy cannot enable <strong>api_key</strong>, tokens, passwords, private keys or bypass identity/delegation rules.</p>
          </section>
          <section>
            <h3>Human authorization and remediation</h3>
            <p><strong>Authorize remediation</strong> records the human business decision for an allowed action and binds the exact policy version/hash. <strong>Execute protected remediation</strong> claims the approved action before sending the side effect and uses a one-time capability bound to the persisted action and policy provenance. <strong>Verify external state</strong> performs an independent read-back and never sends the side effect again.</p>
          </section>
          <section>
            <h3>Execution and verification states</h3>
            <p><strong>EXECUTING</strong> means execution is in progress. <strong>PENDING_VERIFICATION</strong> means the external action was accepted but completion is not proven. <strong>COMPLETED</strong> requires independent verification of the expected state. <strong>UNVERIFIED</strong> means the result is ambiguous, policy binding could not be confirmed or the observed state does not match. <strong>FAILED</strong> means a known failure. An HTTP success response alone is never enough to display COMPLETED.</p>
          </section>
          <section>
            <h3>Retry rule</h3>
            <p>A retry keeps the same logical Request ID but receives a new Trace ID, so idempotency and observability stay independent. Repeating execution for an already claimed action reconciles persisted state instead of intentionally sending a second side effect. An ambiguous outcome remains UNVERIFIED and can be read back only when a verifiable operation ID exists.</p>
          </section>
          <section>
            <h3>Evidence states</h3>
            <p><strong>PASS</strong> is an observed result that matched the expected security outcome. <strong>FAIL</strong> is an observed mismatch. <strong>NOT RUN</strong> means the scenario was not executed and is never counted as proof. Evidence metadata includes the exact contract, WASM, policy version/hash and T3N trust provenance for the run.</p>
          </section>
          <section>
            <h3>Rules and permissions</h3>
            <p>Application sign-in does not grant T3N authority. The agent needs the exact delegation functions, scopes and hosts. Operational policy is read by the TEE from private T3N KV, not supplied by React, Java or the model. DENY and REDACT cannot be promoted to execution by the interface. Critical remediation requires human authorization plus the one-time execution capability, and completion additionally requires independent read-back. A Trace ID is correlation metadata only; it grants no authority and cannot be used to access another incident or action. Incident retention is controlled by the server, not by browser input, and expired incident content cannot be retrieved through the incident API.</p>
          </section>
          <section>
            <h3>Main flow</h3>
            <p>1. Sign in. 2. Read the trust flow and confirm whether T3N controls are available. 3. Enter a non-sensitive prompt. 4. Inspect the proposal. 5. Observe DENY, REDACT or ALLOW together with policy version/hash. 6. Inspect the current incident and its automatic expiration date. 7. For an allowed remediation, authorize it as a human operator. 8. Execute the protected action once; the approved policy provenance is rechecked before egress. 9. Treat acceptance as pending verification. 10. Verify the external state. 11. Review the Execution Trace for technical correlation, the Business Audit Trail for persisted business events, and Proof &amp; evidence for reproducible T3N proof. 12. Open technical details when contract, policy, delegation or trust-provenance metadata is needed. Expired incident data is removed by the server retention process.</p>
          </section>
          <section>
            <h3>Messages and error states</h3>
            <p>Sensitive prompt content is rejected before reaching the external provider. Incident content containing a high-confidence sensitive literal is rejected with HTTP 422 before persistence and the response does not echo that literal. Provider, T3N, policy-KV or trust-boundary failures fail closed. A missing or corrupt policy returns DENY without fabricated provenance. Expired application sessions require sign-in again. Rate-limited sign-in follows the server retry interval. A policy change after authorization blocks protected execution. Ambiguous execution remains UNVERIFIED and is not automatically re-executed. Error messages and trace metadata must not expose private values, passwords, credentials, capabilities, request bodies or raw headers.</p>
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
