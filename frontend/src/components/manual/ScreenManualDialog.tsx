import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { BookOpen, X } from 'lucide-react';

const FOCUSABLE_SELECTOR = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled])', 'select:not([disabled])',
  'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])',
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
      if (event.key === 'Escape') { event.preventDefault(); close(); return; }
      if (event.key !== 'Tab') return;
      const focusable = focusableElements(dialog);
      if (focusable.length === 0) { event.preventDefault(); dialog.focus(); return; }
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
      if (previousAriaHidden === null || previousAriaHidden === undefined) appRoot?.removeAttribute('aria-hidden');
      else appRoot?.setAttribute('aria-hidden', previousAriaHidden);
    };
  }, [open]);

  const dialog = open ? createPortal(
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && close()}>
      <section ref={dialogRef} tabIndex={-1} className="modal-panel" role="dialog" aria-modal="true" aria-labelledby="screen-manual-title" aria-describedby="screen-manual-purpose">
        <div className="modal-header">
          <div><p className="eyebrow">Screen Manual</p><h2 id="screen-manual-title">Incident Response Dashboard</h2></div>
          <button ref={closeButtonRef} type="button" className="icon-button" aria-label="Close Screen Manual" title="Close Screen Manual" onClick={close}><X aria-hidden="true" /></button>
        </div>
        <div className="manual-content">
          <section>
            <h3>Purpose</h3>
            <p id="screen-manual-purpose">This screen demonstrates incident response with separation between AI proposal, Guard runtime policy, human authorization, Protected Executor, protected execution, independent verification, and audit provenance. <strong>Protection flow</strong> operates the workflow and includes the <strong>Incident workspace</strong> for resuming any active incident, including signals received from authenticated enterprise integrations, without turning the demonstration scenario into the case identity. M2M intake creates only the minimized incident and never evaluates policy, authorizes, executes, or verifies remediation automatically. <strong>Executive demo</strong> communicates the same runtime state in a compact format, and <strong>Measured control impact</strong> aggregates persisted results within retention. The model chooses the action and field names but does not supply the trusted normal values that are executed. Supported private data remains logical references until resolution inside protected execution.</p>
          </section>
          <section>
            <h3>Trust runtime</h3>
            <p><strong>Guard runtime</strong> is the self-hosted service that keeps authority outside the model. It enforces the policy, checks the one-time human-authorization capability, performs protected execution and independent read-back, and keeps a tamper-evident, hash-chained activity log. The Proposal Agent and the Protected Executor are separate callers, each with its own token and explicit function grants, so the proposal side can only request evaluation and only the executor can execute or verify. The security endpoint credential and the verified email are held only by Guard runtime and resolved at egress; the browser, model, and Java backend never receive them.</p>
          </section>
          <section>
            <h3>Areas, fields and actions</h3>
            <p><strong>Protection flow</strong> contains Business Outcome, Measured control impact, Incident workspace, scenario, prompt, proposal, decision, next permitted action, human authorization, execution, retention, and the activity rail. The workspace shows severity, origin type, source, received time, operational state, and <strong>Next action</strong> for each active incident; the <strong>All / External / Demo</strong> filter changes only the view, and selecting a row only opens the case. <strong>Trust Flow</strong> summarizes AI, Policy, Human, Execute, and Verify. <strong>Protected execution integration</strong> shows execution endpoint, independent verification endpoint, protected credential, first-party remediation adapter, policy-host authorization, Executor grants, and operational workflow as separate facts. It is a read-only configuration and authorization view and does not perform remediation or claim endpoint health. Every Guard runtime readiness fact is tri-state: <strong>Yes</strong> and <strong>No</strong> are shown only after a valid observation, while an inconclusive read is shown as <strong>Unknown</strong>; a missing host is shown as <strong>Not configured</strong> only when that absence was actually observed. The first-party adapter is observed independently and may remain <strong>Configured</strong> while Guard runtime facts are <strong>Unknown</strong>. When readiness is <strong>UNKNOWN</strong>, <strong>Readiness diagnostic</strong> shows an allowlisted failure category plus a safe explanation without exposing secrets, private URLs, paths, queries, fragments, stack traces, or raw runtime errors. <strong>Requested fields</strong>, <strong>Allowed for egress</strong>, <strong>Removed before egress</strong>, <strong>Trusted synthetic values</strong>, and <strong>Protected egress payload</strong> explain minimization. For notification, <strong>Logical private reference</strong> shows only <code>verified_email</code>, <strong>Resolution boundary</strong> shows GUARD RUNTIME PROTECTED EXECUTION, and <strong>Plaintext visible to app</strong> remains NO. <strong>Authorized by</strong>, <strong>Authorized at</strong>, and <strong>Execution principal</strong> show persisted human provenance. <strong>One-time authorization proof</strong>, <strong>Guard runtime execution proof check</strong>, and <strong>Protected Executor identity</strong> make the separation between human authorization and Executor identity visible without exposing the token.</p>
          </section>
          <section>
            <h3>Human access and permissions</h3>
            <p>The session shows the authenticated principal, its authorities, and whether <strong>Enterprise SoD</strong> is active. <strong>ANALYST</strong> creates incidents, requests analysis, records proposals, and evaluates policy. <strong>APPROVER</strong> records human authorization. <strong>EXECUTOR</strong> executes and verifies protected remediation. <strong>AUDITOR</strong> is read-only and can inspect state, history, trace, aggregated metrics, workspace, and audit evidence.</p>
            <p>Permissions are enforced by the backend; hiding a browser button does not grant or revoke authority. Opening an incident from the workspace is read/navigation only and does not authorize, execute, or verify anything. In enterprise mode, the same principal that authorized a remediation cannot execute or verify that remediation, even if it has multiple authorities. In local/demo mode, one configured account may receive all authorities without being presented as enterprise IAM.</p>
          </section>
          <section>
            <h3>Executive Demo</h3>
            <p>The <strong>Executive demo</strong> tab is a projection of the same runtime state; it does not create a parallel incident, decision, authorization, execution, or evidence path. The reading order is deliberately organized as <strong>business problem → observed outcome → measured operational impact → authority mechanism → technical proof</strong>. The headline first explains that AI agents can participate in sensitive workflows without receiving security authority over private data, policy decisions, or critical actions. The thesis <strong>AI can propose. Policy decides. Humans authorize. Guard runtime executes.</strong> remains in the <strong>Trust path</strong> section to explain the mechanism after the value is understood. Before analysis, the outcome is <strong>NOT YET OBSERVED</strong>. DENY produces <strong>BLOCKED BEFORE PROTECTED EGRESS</strong>, REDACT produces <strong>MINIMIZATION REQUIRED</strong>, and ALLOW without approval produces <strong>HUMAN AUTHORIZATION REQUIRED</strong>. Approval without a side effect remains <strong>AUTHORIZED / NOT EXECUTED</strong>; PENDING_VERIFICATION remains <strong>ACCEPTED / NOT VERIFIED</strong>. UNVERIFIED and FAILED are never presented as success.</p>
            <p><strong>Measured control impact</strong> is a compact projection of four values already calculated by the backend: blocked, minimized, verified, and median decision. It does not create a second calculation source. <strong>Proof at a glance</strong> shows facts observed in the live <code>SystemStatus</code> and the current decision: Policy evaluation, Protected remediation, Identity separation, Effective access, Enterprise integration, and Policy version; missing state appears as <strong>NOT OBSERVED</strong>. <strong>GUARD RUNTIME LIVE / READY</strong> requires protected remediation ready and Enterprise integration READY; any other observed status is <strong>INCOMPLETE</strong>, and a missing status is <strong>NOT READY</strong>. Integration <strong>READY</strong> does not prove reachability or service success. Executive Demo has no Analyze, Authorize, Execute, or Verify buttons. When a persisted incident is resumed from the workspace and no stored scenario binding exists, Executive Demo says <strong>Persisted incident</strong> and does not invent Business risk or Protected asset from the currently selected demo scenario. The screen does not convert operational metrics into money saved, breaches avoided, guaranteed compliance, or a percentage of risk reduction.</p>
          </section>
          <section>
            <h3>Business Outcome</h3>
            <p>Business Outcome derives risk, asset, action, policy, authorization, execution, and verification from observed state. Missing observation remains <strong>Not yet observed</strong>, and the absence of a verifiable conclusion remains <strong>Not verified yet</strong>. <strong>Time to policy decision</strong> = <code>decision.evaluatedAt - action.createdAt</code>. <strong>Time to verified outcome</strong> = <code>remediation.completedAt - action.createdAt</code> only when state is COMPLETED. The system does not calculate money saved, breaches avoided, SLA, or ROI. For notification, COMPLETED requires independent read-back <strong>DELIVERED</strong> with <code>recipient_resolved=true</code>; an isolated 2xx remains PENDING_VERIFICATION. For a resumed case without a persisted scenario, the panel omits static scenario metadata instead of associating the incident with an unproven risk or target outcome.</p>
          </section>
          <section>
            <h3>Measured control impact</h3>
            <p>The aggregate summary uses only persisted data still covered by retention. <strong>Evaluated actions</strong> counts observed policy decisions. <strong>Blocked before egress</strong> counts DENY decisions. <strong>Minimized decisions</strong> counts REDACT decisions. <strong>Verified outcomes</strong> counts executions in COMPLETED, a state that already requires independent read-back. The <strong>Retained</strong>, <strong>24 hours</strong>, and <strong>7 days</strong> filters change only the read window.</p>
            <p><strong>Observed block rate</strong> = DENY / evaluated decisions × 100. <strong>Verified completion</strong> = COMPLETED / (COMPLETED + UNVERIFIED + FAILED) × 100. EXECUTING and PENDING_VERIFICATION do not enter the finalized denominator. When the denominator is zero, the screen shows <strong>NOT OBSERVED</strong>, never an invented 0%.</p>
            <p><strong>Median policy decision</strong> uses <code>evaluatedAt - action.createdAt</code> latencies. <strong>Median verified outcome</strong> uses only COMPLETED and <code>completedAt - action.createdAt</code>. Negative or inconsistent durations are excluded from the median. <strong>Redacted normal field names</strong> and <strong>Redacted private references</strong> count names/categories removed by policy; they do not count bytes, people, or private values.</p>
            <p>The requested window never exceeds configured retention; purged data is not reconstructed. The aggregate API does not return prompt, username, normal payload, or private value. <strong>Financial ROI is NOT MEASURED.</strong> The product does not infer money saved, breaches avoided, percentage risk reduction, SLA, or compliance.</p>
          </section>
          <section>
            <h3>Incident workspace</h3>
            <p>The workspace lists all active incidents covered by retention using an operational summary calculated by the backend. <strong>Need attention</strong> counts only items whose state requires review or a next action. States include <strong>Needs analysis</strong>, <strong>Policy evaluation required</strong>, <strong>Blocked by policy</strong>, <strong>Needs human approval</strong>, <strong>Execution pending</strong>, <strong>Execution in progress</strong>, <strong>Verification pending</strong>, <strong>Verified complete</strong>, <strong>Unverified / review required</strong>, <strong>Failed / review required</strong>, and review states when the persisted combination does not support a safe conclusion.</p>
            <p><strong>Source filter</strong> provides <strong>All</strong>, <strong>External</strong>, and <strong>Demo</strong>. External is determined by <code>originType=EXTERNAL</code> persisted by the backend, never by title, queue position, or source text. The source of an external incident is derived on the server from the authenticated integration, for example <strong>Approved integration: Security automation</strong>; the M2M request does not choose this value. Demo covers non-external cases created by the application, including synthetic catalog scenarios. Cases created manually through the human API also remain application-origin cases and therefore are not presented as external integration events.</p>
            <p>Each row shows origin, <strong>Source</strong>, <strong>Received</strong>, state, and <strong>Next action</strong>. Next action is triage guidance derived from persisted state; it is not a privileged button or an authorization. Selecting a case clears the previous detail and loads Incident, the latest Action Proposal, Policy Decision, Remediation, Trace, and Audit for that incident. The detail shows <strong>Source</strong> and <strong>Received at</strong> without exposing the integration credential.</p>
            <p>Authenticated M2M intake is separate from the human session and CSRF. It accepts only minimized operational metadata, applies the same domain retention and audit rules, and uses idempotency by integration + external event id. Redelivery of the same event by the same integration resumes the same incident; the same identifier sent by different integrations remains independent. Intake tokens are backend-only configuration and are never sent to the browser, DOM, or audit.</p>
            <p>Receiving an external incident does not call the Agent, policy, human authorization, Protected Executor, execution, or verification. The workspace contains no Authorize, Execute, or Verify action. Those actions remain in the existing detail and stay subject to authorities and SoD rules. If an incident expires between listing and opening, the screen removes it from the queue and reports that it is no longer active. Failure to load the queue or detail offers <strong>Retry</strong>; zero incidents shows an empty state and is not treated as an error.</p>
            <p>The scenario catalog remains a separate demonstration tool. Selecting a scenario does not select or rename a persisted incident. Resuming a case from the workspace does not attempt to infer its scenario from title, severity, source, or action.</p>
          </section>
          <section>
            <h3>Prompt, scenarios and privacy</h3>
            <p>Scenarios use synthetic prompts. Analyze with agent and Ask agent for minimum proposal call the configured provider without granting permissions. The prompt guard covers supported structured classes, but an accepted prompt does not mean <strong>PII-free</strong>, safe, or equivalently certified. Private values and secrets must not be entered in the prompt.</p>
            <p>In the <strong>notify-security</strong> flow, the browser, model, and Java backend carry only the logical reference <code>verified_email</code>. The profile marker is created exclusively inside Guard runtime, and only its protected egress replaces it with the verified email right before sending. Resolved plaintext may exist transiently in protected egress and the authorized external service, but it is not returned by APIs, Business Outcome, or Audit Trail.</p>
          </section>
          <section>
            <h3>Callers, function grants and effective authorization</h3>
            <p>Tenant, Proposal Agent, and Protected Executor are distinct principals. The Proposal Agent and the Protected Executor are separate Guard runtime callers with their own tokens and explicit function grants: Proposal uses <code>evaluate-action</code>; Executor uses <code>execute-remediation</code> and <code>verify-remediation</code>. <strong>Effective Guard runtime access</strong> is confirmed by Guard runtime for that caller's own authenticated token. <strong>Confirmed</strong> requires every required function to be granted; <strong>Denied</strong> means a required function is not granted or the token was rejected; <strong>Unknown</strong> represents an error or inconclusive response and always fails closed.</p>
          </section>
          <section>
            <h3>Readiness</h3>
            <p><strong>Proposal evaluation</strong> requires resolved Tenant, Proposal caller, and contract, an ACTIVE function grant, and confirmed effective access. <strong>Protected remediation authorization</strong> additionally requires an authenticated Executor caller, ACTIVE grant, and confirmed effective access. This Guard runtime authorization is independent from protected execution integration configuration: Guard runtime needs all three protected values, execution URL, verification URL, and machine credential, in its own environment. A credential by itself is intentionally insufficient. Missing configuration is not reported as a Guard runtime denial and execution remains blocked.</p>
            <p><strong>Enterprise integration UNKNOWN</strong> remains fail-closed and includes only an allowlisted diagnostic category: <code>POLICY_UNAVAILABLE</code>, <code>POLICY_INVALID</code>, <code>PRIVATE_CONFIGURATION_UNAVAILABLE</code>, <code>ENDPOINT_CONFIGURATION_INVALID</code>, <code>DELEGATION_UNAVAILABLE</code>, or <code>TRUST_RUNTIME_UNAVAILABLE</code>. Facts that were not observed remain <strong>Unknown</strong> across Guard runtime, backend, and browser instead of being converted to <strong>No</strong> or <strong>Not configured</strong>. A confirmed false value remains <strong>No</strong>, and a confirmed missing endpoint remains <strong>Not configured</strong>. Authorization, evaluation, and protected remediation still fail closed whenever any required fact is unknown. The diagnostic identifies which protected-readiness boundary could not be confirmed; it never includes a raw runtime error, machine credential, full private URL, path, query, fragment, or stack trace. <strong>NONE</strong> is used when no failure diagnostic applies.</p>
            <p><strong>First-party remediation adapter</strong> reports whether the backend has its own machine credential configured for the controlled Privacy Guard adapter. This status is intentionally separate from Guard runtime policy and grant readiness and from the private configuration held by Guard runtime. The first-party adapter does not imply a third-party provider, and <strong>READY</strong> does not prove network reachability or endpoint health.</p>
          </section>
          <section>
            <h3>Policy, minimization, human authorization and execution</h3>
            <p>DENY blocks. REDACT may continue only when the required minimum survives and the re-evaluated subset becomes ALLOW. For <code>revoke-credential</code>, the required normal minimum is <code>incident_id</code>, <code>credential_id</code>, and <code>reason</code>, with no private refs. For <code>notify-security</code>, the required normal minimum is <code>incident_id</code>, <code>severity</code>, and <code>summary</code>, with exactly <code>private_refs=["verified_email"]</code>. Removed before egress is never copied into the execution request.</p>
            <p>After human authorization, the backend emits a signed one-time <strong>v2</strong> capability with <strong>Ed25519</strong> at execution time. It binds normalPayloadHash, action/resource/purpose, fields, private references, policy version/hash, Protected Executor identity, approved destination, authenticated-principal hash, authorization timestamp, issued/expiry, and nonce. The private key remains in the backend; Guard runtime receives only public verification material. There is no silent downgrade to the legacy format.</p>
            <p><strong>Human authorization</strong> records the application's authenticated principal, not a civil identity or a Guard runtime caller. The capability does not send the username; it binds the SHA-256 of the canonical principal and the persisted timestamp. Legacy authorizations without provenance require <strong>REAUTHORIZATION REQUIRED</strong>. Under Enterprise SoD, the executor principal must differ from the approver; this rule is enforced by the backend before protected egress.</p>
            <p><strong>Guard runtime execution proof check</strong>: the backend sends the capability to <code>execute-remediation</code> with the Executor caller's token. Before reading the security endpoint configuration or credential, or starting HTTP, Guard runtime verifies signature, key id, expiration, and claims, and consumes the nonce in its replay store. An Executor call without a capability, an expired or tampered capability, a mismatched request, or a reused nonce fails closed. The interface does not claim that Guard runtime verified the human's civil identity; Guard runtime verifies the signed capability emitted by the backend after authentication and authorization.</p>
            <p><strong>Execute protected credential revocation</strong> and <strong>Execute protected security notification</strong> require an authorized Executor + valid capability, approved destination, compatible current policy, minimized payload, and ALLOW on re-evaluation. For notification, only Guard runtime adds the <code>verified_email</code> marker to egress. Acceptance is not completion; revocation requires REVOKED, and notification requires DELIVERED + <code>recipient_resolved=true</code> in independent read-back.</p>
            <p>The controlled <strong>first-party remediation adapter</strong> accepts only <code>POST /api/security/remediation/execute</code> and <code>POST /api/security/remediation/verify</code> with <code>Authorization: Bearer</code> using the dedicated remediation credential. Human sessions never substitute for this machine identity. Execute also requires <code>Idempotency-Key</code> equal to the protected <code>request_id</code>; replay of the same request/action returns the same opaque operation id, while reusing the id for another action fails closed. The adapter persists only operation metadata and verification booleans, not recipient, credential id, reason, summary, raw body, or the machine secret.</p>
          </section>
          <section>
            <h3>Local audit integrity and Guard runtime Activity Log</h3>
            <p>The local audit uses <strong>HMAC-SHA256</strong> and is <strong>tamper-evident</strong>, not immutable. <strong>VERIFIED</strong>, <strong>BROKEN</strong>, <strong>KEY_MISMATCH</strong>, and <strong>LEGACY_UNVERIFIED</strong> are distinct states. An old internally consistent snapshot is not claimed as detectable without an external monotonic anchor. Authorization records the approver principal, and execution persists the executor principal obtained from the session; human identity is not accepted in the request body.</p>
            <p>The Guard runtime Activity Log is append-only and hash-chained. In it, evaluate-action must identify the Proposal Agent; execute-remediation and verify-remediation must identify the Protected Executor. Reconciliation with the local HMAC chain requires exact sequence, hash, contract, function, and actor; <strong>Runtime only</strong> marks runtime activity without a matching local event. Local integrity does not fabricate Guard runtime provenance.</p>
          </section>
          <section>
            <h3>Main flow</h3>
            <p>1. Read readiness, Enterprise integration, and the session authority. 2. In Incident workspace, choose an active incident to resume; external incidents already arrive as <strong>External</strong> and begin in <strong>Needs analysis</strong>, while the catalog remains available to start a demo flow. 3. Use Executive demo only for presentation. 4. In Protection flow, as ANALYST, use Analyze with agent when starting a new scenario or propose the minimum response for the selected incident. 5. Review proposal, policy, and minimization. 6. For executable ALLOW/REDACT, check the minimum fields and, for notify-security, only the <code>verified_email</code> reference. 7. As APPROVER, record Human authorization. 8. Under Enterprise SoD, switch to an EXECUTOR principal different from the approver. 9. Execute and observe One-time authorization proof, Guard runtime execution proof check without revealing the token or recipient. 10. Verify the action-specific state through read-back. 11. Accept COMPLETED only after REVOKED or DELIVERED + recipient_resolved. 12. Use Measured control impact for aggregate results within retention. 13. In Audit evidence, review local integrity and Guard runtime provenance.</p>
          </section>
          <section>
            <h3>Messages and error states</h3>
            <p>Provider, Guard runtime, policy, function grant, trust-boundary, or protected adapter failure is never presented as success. A Proposal or Executor grant state that cannot be confirmed is reported as <strong>could not be confirmed</strong>, never as <strong>not active</strong>; <strong>NOT_GRANTED</strong>, <strong>REVOKED</strong>, <strong>SCHEDULED</strong>, and effective <strong>DENIED</strong> retain their specific meanings. Failure to load the Incident workspace or detail offers <strong>Retry</strong>; an incident that expires before being opened is removed from the queue and reported as inactive. A source filter with no results shows a specific empty state without suggesting a service failure. <strong>403 Action not allowed</strong> indicates insufficient human authority. <strong>Separation of duties…different principal</strong> indicates that the approver attempted to execute or verify the same action in enterprise mode; protected egress is not started. Missing human proof, expired proof, invalid signature, invalid key id, body/Executor mismatch, or an already consumed nonce fails closed before protected egress. Protected adapter Bearer missing/invalid returns unauthorized without echoing the credential; malformed or extra execution fields fail closed; an unknown operation returns not found; request/action/state mismatches return a conflict. For notify-security, a missing or extra private ref, literal placeholder, policy-disallowed reference, DELIVERED without <code>recipient_resolved=true</code>, or resolution error remains blocked/UNVERIFIED without echoing the recipient. REAUTHORIZATION REQUIRED requires a new explicit approval. Destination changed requires a new action, evaluation, and authorization. Acceptance without read-back remains PENDING_VERIFICATION or UNVERIFIED. Broken audit integrity blocks protected changes. <strong>NOT OBSERVED</strong> for an aggregate rate or latency means there is no valid denominator/sample, not an invented zero.</p>
          </section>
        </div>
      </section>
    </div>,
    document.body,
  ) : null;

  return (
    <>
      <button ref={triggerRef} type="button" className="button button-secondary manual-trigger" aria-label="Open Screen Manual" title="Open Screen Manual" onClick={() => setOpen(true)}>
        <BookOpen aria-hidden="true" /><span>Screen Manual</span>
      </button>
      {dialog}
    </>
  );
}
