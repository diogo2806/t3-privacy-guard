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
            <p id="screen-manual-purpose">This dashboard demonstrates a simple enterprise rule: AI may propose an action, but it cannot authorize itself or declare a critical action complete. You can test an adversarial or legitimate prompt, inspect the independent policy decision, authorize an allowed remediation as a human operator, execute it through T3N and verify the external result independently.</p>
          </section>
          <section>
            <h3>How to read the trust flow</h3>
            <p><strong>AI proposal</strong> shows whether a structured action proposal is available. <strong>Policy</strong> returns DENY, REDACT or ALLOW. DENY blocks the proposal, REDACT requires minimization and ALLOW only permits the proposal to continue. <strong>ALLOW does not mean executed.</strong> Critical remediation still requires explicit human authorization. <strong>COMPLETED appears only after independent read-back verifies the expected external state.</strong></p>
          </section>
          <section>
            <h3>Views and filters</h3>
            <p><strong>Protection demo</strong> contains the prompt, proposal, policy decision, human authorization, protected execution, verification and audit trail. <strong>Proof &amp; evidence</strong> shows which testnet outcomes were actually observed. The screen has no business-data filters; these two views organize the journey. Technical T3N identifiers, contract and delegation details remain available under <strong>Show technical details</strong> without dominating the main flow.</p>
          </section>
          <section>
            <h3>Prompt field and actions</h3>
            <p>The prompt is untrusted input and accepts up to 4,000 characters. Do not paste literal private values, credentials or secrets. <strong>Load attack prompt</strong> prepares a safe adversarial instruction without real sensitive values. <strong>Load safe prompt</strong> prepares a legitimate minimum-scope instruction. <strong>Ask agent</strong> sends the prompt to the configured provider. <strong>Run attack scenario</strong> executes the documented adversarial demo through the same provider path.</p>
          </section>
          <section>
            <h3>Proposal and private-data boundary</h3>
            <p>The model may propose only the action, resource, purpose, optional host, field names and supported logical private-data references. It cannot choose trusted identities, policy decisions, approvals or execution proof. Private values remain outside the browser and model; supported logical references are resolved only inside the protected T3N execution boundary.</p>
          </section>
          <section>
            <h3>T3N trust provenance</h3>
            <p><strong>Trust anchor VERIFIED</strong> means the official signed T3N manifest established the cluster trust boundary for the authenticated sessions. <strong>Rollback floor PERSISTED</strong> means the accepted trust-manifest version is stored as a monotonic high-water mark across gateway restarts. The displayed trust-manifest version is that observed high-water version. These states are not per-request hardware attestation. Trust-manifest unavailability, rollback rejection, corrupted persisted state or a missing version fail closed and must not appear as a green success state.</p>
          </section>
          <section>
            <h3>Decision states</h3>
            <p><strong>DENY</strong> blocks the proposal before protected egress. <strong>REDACT</strong> requires a smaller data scope before the action may continue. <strong>ALLOW</strong> means policy permits the proposal, but it is not human approval, execution or completion.</p>
          </section>
          <section>
            <h3>Human authorization and remediation</h3>
            <p><strong>Authorize remediation</strong> records the human business decision for an allowed action. <strong>Execute protected remediation</strong> claims the approved action before sending the side effect and uses replay-resistant execution data. <strong>Verify external state</strong> performs an independent read-back and never sends the side effect again.</p>
          </section>
          <section>
            <h3>Execution and verification states</h3>
            <p><strong>EXECUTING</strong> means execution is in progress. <strong>PENDING_VERIFICATION</strong> means the external action was accepted but completion is not proven. <strong>COMPLETED</strong> requires independent verification of the expected state. <strong>UNVERIFIED</strong> means the result is ambiguous or does not match. <strong>FAILED</strong> means a known failure. An HTTP success response alone is never enough to display COMPLETED.</p>
          </section>
          <section>
            <h3>Evidence states</h3>
            <p><strong>PASS</strong> is an observed result that matched the expected security outcome. <strong>FAIL</strong> is an observed mismatch. <strong>NOT RUN</strong> means the scenario was not executed and is never counted as proof.</p>
          </section>
          <section>
            <h3>Rules and permissions</h3>
            <p>Application sign-in does not grant T3N authority. Policy must allow the exact action and scope, critical remediation requires human authorization, protected execution requires its runtime controls, and completion additionally requires independent read-back. DENY and REDACT cannot be promoted to execution by the interface.</p>
          </section>
          <section>
            <h3>Main flow</h3>
            <p>1. Sign in. 2. Read the trust flow and confirm whether T3N controls are available. 3. Enter a non-sensitive prompt. 4. Inspect the proposal. 5. Observe DENY, REDACT or ALLOW. 6. For an allowed remediation, authorize it as a human operator. 7. Execute the protected action once. 8. Treat acceptance as pending verification. 9. Verify the external state. 10. Review Proof &amp; evidence, the audit trail and technical details when needed.</p>
          </section>
          <section>
            <h3>Messages and error states</h3>
            <p>Sensitive prompt content is rejected before reaching the external provider. Provider, T3N or trust-boundary failures fail closed. Expired application sessions require sign-in again. Rate-limited sign-in follows the server retry interval. Ambiguous execution remains UNVERIFIED and is not automatically re-executed. Error messages must not expose private values, passwords, credentials, request bodies or raw headers.</p>
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
