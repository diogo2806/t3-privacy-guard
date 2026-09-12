import { useEffect, useRef, useState } from 'react';
import { BookOpen, X } from 'lucide-react';

export function ScreenManualDialog() {
  const [open, setOpen] = useState(false);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (open) closeButtonRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [open]);

  return (
    <>
      <button
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
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setOpen(false)}>
          <section className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="screen-manual-title">
            <div className="modal-header">
              <div>
                <p className="eyebrow">Manual da Tela</p>
                <h2 id="screen-manual-title">Incident Response Dashboard</h2>
              </div>
              <button ref={closeButtonRef} type="button" className="icon-button" aria-label="Close Screen Manual" title="Close" onClick={() => setOpen(false)}>
                <X aria-hidden="true" />
              </button>
            </div>
            <div className="manual-content">
              <section><h3>Purpose</h3><p>Demonstrates how T3 Privacy Guard handles a compromised AI agent: malicious exfiltration is denied while an authorized remediation can still run without exposing the credential.</p></section>
              <section><h3>Information shown</h3><p>Live gateway/T3N readiness, tenant and agent DIDs when available, registered contract identity/version, current incident, proposed actions, policy decisions, remediation state and sanitized audit history.</p></section>
              <section><h3>Actions</h3><p><strong>Run attack scenario</strong> creates a critical incident and asks T3N to evaluate an exfiltration attempt. <strong>Prepare safe remediation</strong> creates the minimum legitimate revoke request. <strong>Authorize remediation</strong> records explicit business authorization. <strong>Execute protected remediation</strong> invokes the TEE contract and secretless egress. <strong>Refresh status</strong> reloads live capability state.</p></section>
              <section><h3>Filters and fields</h3><p>This focused demo has no search filters or editable credential fields. Action metadata contains request id, action, resource, purpose, destination host and requested field names only. Secret values are intentionally absent from the UI and DOM.</p></section>
              <section><h3>Rules and permissions</h3><p>Authentication does not imply authorization. The agent needs an active T3N delegation for the exact contract function, scopes and outbound host. A DENY or REDACT decision cannot authorize remediation. The credential is stored in the tenant private map and is readable only by the contract.</p></section>
              <section><h3>Main flow</h3><p>1. Confirm live status. 2. Run the attack and observe DENY. 3. Prepare the safe action and observe ALLOW. 4. Explicitly authorize it. 5. Execute remediation. 6. Review the audit trail.</p></section>
              <section><h3>States and messages</h3><p><strong>ALLOW</strong> means policy permits the proposed minimum action, not that execution already happened. <strong>REDACT</strong> means unnecessary fields must be removed. <strong>DENY</strong> blocks the action. Unavailable T3N capabilities are shown as unavailable and never presented as successful verification.</p></section>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
