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
              <section><h3>Purpose</h3><p id="screen-manual-purpose">Demonstrates that a manipulated AI model cannot grant itself authority, retrieve private profile values, rewrite the active operational policy or cause an external side effect to be reported as completed without independent verification. T3N policy, explicit human authorization, one-time execution proof and external read-back are separate controls.</p></section>
              <section><h3>AI agent prompt</h3><p>The Prompt field accepts up to 4,000 characters and is untrusted input. <strong>Load attack prompt</strong> fills a credential-exfiltration instruction. <strong>Load safe prompt</strong> fills a minimum legitimate instruction. <strong>Ask agent</strong> uses the configured real provider. <strong>Run attack scenario</strong> sends the documented attack prompt through the same provider path.</p></section>
              <section><h3>Agent proposal</h3><p>The model may provide only action, resource, purpose, optional host, requested field names and enumerated logical private references. For private contact data the supported reference is <strong>Verified email</strong>; the model never receives the email itself. Decision, override, DID, credentials, secrets, API keys, policy documents and literal T3N placeholders are rejected.</p></section>
              <section><h3>Private data boundary</h3><p>The Rust/WASM contract maps approved logical references to supported T3N profile markers. T3N resolves the private value only during protected egress. React, Java, gateway responses, audit records and evidence retain only non-sensitive metadata and never render the resolved plaintext.</p></section>
              <section><h3>Authority separation</h3><p>The AI provider never receives T3N tenant/agent keys, remediation credentials, service tokens, one-time capabilities, operational policy authority or resolved profile values. Agent DID and tenant DID come from authenticated T3N sessions. The model cannot select identities, contract, policy decision or human authorization proof.</p></section>
              <section><h3>Operator session</h3><p>The operator uses runtime-only application credentials. This identity is separate from T3N tenant, agent and AI-provider identities. Signing out invalidates the application session.</p></section>
              <section><h3>Views</h3><p><strong>Demo</strong> contains AI prompt, proposal, private-data categories, policy decision, policy provenance, authorization, execution, verification and audit. <strong>Evidence</strong> displays only sanitized, internally consistent T3N evidence. Evidence refresh never invokes the model or executes testnet actions from the browser.</p></section>
              <section><h3>Decision states</h3><p><strong>DENY</strong> blocks the proposal. <strong>REDACT</strong> requires minimization. <strong>ALLOW</strong> accepts the proposal under the active versioned policy but does not mean human approval, egress or completion.</p></section>
              <section><h3>Policy version and hash</h3><p><strong>Policy version</strong> identifies the operational rules loaded by the Rust/WASM contract from the private T3N KV map. <strong>Policy hash</strong> is the deterministic SHA-256 of the canonical policy document applied to that decision. These fields prove which policy content produced the decision; they are not hardware attestation. If either value is unavailable on a legacy decision, protected remediation is blocked and a new action must be evaluated.</p></section>
              <section><h3>What policy can change</h3><p>The versioned policy may enable actions and configure purpose, allowed hosts, allowed field names, supported logical private references, host requirement and the human-authorization flag. Contract invariants remain compiled in WASM: schema/size limits, fail-closed behavior, T3N identity boundaries, secret-field prohibition, private-reference vocabulary and safe host validation. A KV policy cannot enable <strong>api_key</strong>, tokens, passwords or other forbidden secret classes.</p></section>
              <section><h3>Remediation actions</h3><p><strong>Authorize remediation</strong> records human business authorization only and binds the current policy version/hash. <strong>Execute protected remediation</strong> atomically claims the action before egress, uses the stable request ID as idempotency key and sends a one-time capability bound to the exact ALLOW action and policy metadata. If the active T3N policy changes after authorization, execution is rejected and must be evaluated again. The external acknowledgement moves the execution only to pending verification. <strong>Verify external state</strong> performs read-back and never sends the side effect again.</p></section>
              <section><h3>Execution and verification states</h3><p><strong>EXECUTING</strong> means the durable claim exists. <strong>PENDING_VERIFICATION</strong> means the external service accepted the request but its final state is not yet proven. <strong>COMPLETED</strong> exists only after read-back verifies the expected state. <strong>UNVERIFIED</strong> means the outcome is ambiguous, verification is unavailable, policy binding could not be confirmed or the observed state does not match. <strong>FAILED</strong> is reserved for a known failure that is safe to classify as failed. An HTTP 2xx alone is never shown as COMPLETED.</p></section>
              <section><h3>Retry rule</h3><p>Repeating execution for the same action reconciles the durable claim instead of sending another external side effect. If a process restarts after the request may have been sent but before an operation ID is persisted, the state becomes UNVERIFIED and automatic re-execution is blocked. A manual verification is offered only when an operation ID exists.</p></section>
              <section><h3>Evidence states</h3><p><strong>PASS</strong> means observed result matched expectation. <strong>FAIL</strong> means it did not. <strong>NOT RUN</strong> means a scenario was not executed and is never counted as PASS. Profile resolution, versioned policy setup or external verification is not claimed live unless matching testnet evidence exists.</p></section>
              <section><h3>Rules and permissions</h3><p>Application authentication does not imply T3N authorization. The agent needs active delegation for the exact functions, scopes and host. DENY/REDACT cannot be authorized. Privileged execution requires service authentication plus the one-time capability. Private references are enumerated. Operational policy is read by the TEE from T3N KV, not supplied by React, Java or the model. Completion additionally requires independent read-back.</p></section>
              <section><h3>Main flow</h3><p>1. Sign in. 2. Confirm tenant, agent, contract and delegation. 3. Submit attack prompt and inspect the model proposal. 4. Observe T3N DENY/REDACT/ALLOW plus policy version/hash. 5. Prepare an allowed remediation. 6. Authorize it explicitly. 7. Execute once; the action and approved policy provenance are bound before egress. 8. Observe accepted/pending verification rather than assuming success from 2xx. 9. Verify external state until VERIFIED or leave the action UNVERIFIED for investigation. 10. Review Evidence and audit history.</p></section>
              <section><h3>Messages and errors</h3><p>Provider, T3N or policy-KV failures fail closed. A missing/corrupt policy returns a DENY state without fabricated provenance. A 401 means session/internal authentication is missing; 403 means authorization/CSRF/capability does not allow an action; replay is rejected as conflict. A policy change after authorization prevents protected execution. An ambiguous execution is shown as UNVERIFIED and is not automatically retried. Error messages never expose provider keys, T3N keys, profile values, request/response bodies or raw headers.</p></section>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
