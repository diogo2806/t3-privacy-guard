import { useEffect, useRef, useState } from 'react';
import { BookOpen, X } from 'lucide-react';

export function ScreenManualDialog() {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  const close = () => {
    setOpen(false);
    requestAnimationFrame(() => triggerRef.current?.focus());
  };

  useEffect(() => {
    if (open) closeButtonRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') close();
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open]);

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className="button button-secondary manual-trigger"
        aria-label="Open Screen Manual"
        title="Manual da Tela / Screen Manual"
        onClick={() => setOpen(true)}
      >
        <BookOpen aria-hidden="true" />
        <span>Screen Manual</span>
      </button>

      {open && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && close()}>
          <section className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="screen-manual-title" aria-describedby="screen-manual-purpose">
            <div className="modal-header">
              <div><p className="eyebrow">Manual da Tela</p><h2 id="screen-manual-title">Incident Response Dashboard</h2></div>
              <button ref={closeButtonRef} type="button" className="icon-button" aria-label="Close Screen Manual" title="Close Screen Manual" onClick={close}><X aria-hidden="true" /></button>
            </div>
            <div className="manual-content">
              <section><h3>Purpose</h3><p id="screen-manual-purpose">Demonstrates how T3 Privacy Guard handles a compromised AI agent: malicious exfiltration is denied while an authorized remediation can still run without exposing the credential to the browser, Java backend or AI agent.</p></section>
              <section><h3>Operator session</h3><p>The application operator signs in with credentials configured only in the backend runtime environment. This session is separate from the T3N tenant and agent identities. T3N private keys are never used in the login form. Signing out invalidates the application session immediately.</p></section>
              <section><h3>Information shown</h3><p>After operator authentication, the screen shows gateway/T3N readiness, tenant and agent DIDs when available, contract identity/version, current incident, proposed actions, policy decisions, remediation state and sanitized audit history.</p></section>
              <section><h3>Actions</h3><p><strong>Run attack scenario</strong> creates a critical incident and asks T3N to evaluate an exfiltration attempt. <strong>Prepare safe remediation</strong> creates the minimum legitimate revoke request. <strong>Authorize remediation</strong> records human business authorization but does not execute the action. <strong>Execute protected remediation</strong> invokes the TEE contract and secretless egress. <strong>Refresh status</strong> reloads live capability state. <strong>Sign out</strong> invalidates the operator session.</p></section>
              <section><h3>Filters and fields</h3><p>This focused demo has no search filters or editable credential fields. Action metadata contains request id, action, resource, purpose, destination host and requested field names only. Secret values are intentionally absent from the UI and DOM. The password field exists only during sign-in and is cleared after the attempt.</p></section>
              <section><h3>Rules and permissions</h3><p>Application authentication does not imply T3N authorization. The operator session protects the HTTP business API, while the agent still needs an active T3N delegation for the exact contract function, scopes and outbound host. A DENY or REDACT decision cannot be human-authorized for remediation. The remediation credential remains in the tenant private map and is readable only by the contract.</p></section>
              <section><h3>Main flow</h3><p>1. Sign in as the application operator. 2. Confirm live status. 3. Run the attack and observe DENY. 4. Prepare the safe action and observe ALLOW. 5. Record explicit human authorization. 6. Execute remediation. 7. Review the audit trail. 8. Sign out when finished.</p></section>
              <section><h3>States and messages</h3><p><strong>ALLOW</strong> means policy permits the proposed minimum action, not that execution already happened. <strong>REDACT</strong> means unnecessary fields must be removed. <strong>DENY</strong> blocks the action. A 401 means the operator session is missing or expired and requires sign-in again. A 403 means the current session or CSRF protection does not allow the requested action. Unavailable T3N capabilities are never presented as successful verification.</p></section>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
