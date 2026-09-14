# T3 Privacy Guard — Submission & Judge Guide

## Product position

**T3 Privacy Guard is an enterprise trust runtime for AI agents.** Its purpose is not to make the model itself trustworthy. Its purpose is to keep policy, identity, private-data resolution, business authorization and completion proof outside the model even when the model is manipulated.

The product thesis is intentionally simple:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

The challenge implementation applies that pattern to confidential incident response. The Rust policy recognizes four concrete operational actions: credential revocation, account isolation, incident recording and security notification. The Protection flow exposes all four as business-readable presets. `revoke-credential` and `notify-security` have closed protected execution plus independent read-back contracts; `isolate-account` and `create-incident` remain policy-evaluation scenarios without a protected side-effect executor.

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host`, normal field names and enumerated logical private-data references. It cannot provide a policy decision, DID, override, secret, trusted normal-payload values, execution capability or literal T3N profile placeholder.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM policy through authenticated T3N identities. The Tenant, Proposal Agent and Protected Executor have separate sessions and canonical DIDs. A malicious exfiltration proposal receives `DENY`. For protected execution, Spring materializes trusted synthetic normal values independently from the model-selected field names. Credential revocation requires `incident_id`, `credential_id`, `reason`; security notification requires `incident_id`, `severity`, `summary` plus exactly the logical private reference `verified_email`. A legitimate policy result can be `ALLOW`, or `REDACT` when an unnecessary non-secret field is requested; REDACT can continue only when the action-specific required minimum survives and the minimized set is re-evaluated as `ALLOW` before HTTP.

An authenticated operator must explicitly authorize remediation. Spring emits a short-lived one-time signed capability bound to the exact action, decision, **canonical approved destination**, requested normal fields, `normalPayloadHash`, logical private references, Protected Executor DID and policy provenance.

Delegation is also split into two proofs. A **Member grant** is the Tenant-side record that names the grantee, contract, functions, scopes, hosts and validity window. It proves that a matching grant document exists, but it does not by itself prove that the authenticated principal is effectively authorized at that moment. Only when the matching Member grant is `ACTIVE` does the gateway call T3N `checkDelegation()` through that authenticated Proposal Agent or Protected Executor client. Proposal checks the fixed minimum requirement `evaluate-action` with scopes `incident_id`, `credential_id`, `reason`. Executor independently checks `execute-remediation` plus `verify-remediation` with scopes `incident_id`, `credential_id`, `reason`, `verified_contacts.email.value`. Wildcard requirements are rejected. Only `authorised=true` produces **effective access `ACTIVE`**. `authorised=false` produces `DENIED`; transport, parsing or malformed verdicts produce `UNKNOWN`. Known non-active Member states fail closed without issuing a potentially misleading positive platform check.

For private profile data, the application carries only the logical category `verified_email`. The Rust/WASM contract alone maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`; the real value can be resolved only by T3N during protected egress and is not returned to React, Java, the model or gateway responses. Execution response metadata is minimized, and `operation_id` is accepted only under a bounded opaque identifier grammar so an upstream cannot smuggle an e-mail address back through that field.

Protected remediation is fail-safe under retries. Spring creates a persistent atomic claim before egress. The TEE sends `requestId` as the stable idempotency key, but a 2xx only produces `PENDING_VERIFICATION`. A distinct T3N `verify-remediation` read-back must observe the matching operation and the closed action-specific state. Credential revocation requires `REVOKED`; security notification requires `DELIVERED` and `recipient_resolved=true`. Only then does the business state become `COMPLETED`. Ambiguous outcomes become `UNVERIFIED`; they may be re-verified but are never automatically executed again.

The local business audit has a separate integrity control. New sanitized events are linked in a versioned HMAC-SHA-256 chain per incident, with monotonic local sequence and an authenticated chain head. This makes DB/storage-only changes detectable when the attacker does not have the audit key. The control is deliberately described as **tamper-evident**, never immutable or tamper-proof, and remains independent from T3N Activity Log provenance.

The operational policy used by contract `0.4.0` is versioned in private T3N KV. Each decision carries the exact `policyVersion` and deterministic SHA-256 `policyHash`; critical invariants remain compiled in WASM. Missing or invalid policy fails closed. Human authorization and protected execution are bound to the same version/hash so a policy change after approval cannot silently reuse stale authority. Destination binding is an additional and stricter invariant: a policy may allow hosts A and B, but an operator approval for A cannot be reused for B.

The project reports only verifiable state: `NOT_RUN` never becomes `PASS`, simulated output is not labelled live, profile-placeholder resolution is not labelled proved live until a compatible testnet profile actually executes it, an observed Member grant is not labelled effective authority, external execution is not labelled completed from HTTP acceptance alone, local audit integrity is not labelled immutable storage, and hardware attestation is not claimed without a concrete artifact.

Each live evidence bundle records the full public Git commit SHA and whether the source tree was `CLEAN` or `DIRTY` when evidence generation began. Submission evidence fails closed on a dirty tree by default. The source revision provides reproducibility and public-code traceability; the WASM SHA-256 and policy hash remain the identities of the executed artifacts. None of these fields is described as an independent code audit or hardware attestation.

## Executive Demo presentation contract

`Executive demo` is a presentation-only projection of the same `SystemStatus`, selected scenario, `AgentAnalysis`, `ActionProposal`, `PolicyDecision`, `RemediationExecution` and `EvidenceBundle` already owned by the dashboard. It does not create a second incident, decision, authorization, execution, verification or evidence pipeline. The only action in the view is navigation to the technical Evidence area; the Manual da Tela remains available through the standard `BookOpen` dialog. All state-changing controls stay in `Protection flow`.

Expected 1440×900 composition:

```text
+--------------------------------------------------------------------------------+
| AI can propose. Policy decides. Humans authorize. T3N executes.   [READINESS]  |
+--------------------------------------+-----------------------------------------+
| Business risk                        | Observed outcome                        |
| selected scenario + protected asset  | decision + measured decision time       |
+--------------------------------------+-----------------------------------------+
| AI proposal -> T3N policy -> Human -> Executor -> Verify                       |
+--------------------------------------------------------------------------------+
| Proof at a glance: commit/tree/network/contract/PASS-FAIL-NOT RUN/DIDs/...     |
+--------------------------------------------------------------------------------+
| [Open technical evidence]                                      [Manual da Tela]|
+--------------------------------------------------------------------------------+
```

The view follows the same conservative claim contract as the runtime:

```text
No analysis                     -> NOT YET OBSERVED
DENY                            -> BLOCKED BEFORE PROTECTED EGRESS
REDACT                          -> MINIMIZATION REQUIRED
ALLOW without human approval    -> HUMAN AUTHORIZATION REQUIRED
REMEDIATION_AUTHORIZED only     -> AUTHORIZED / NOT EXECUTED + NOT VERIFIED YET
PENDING_VERIFICATION            -> ACCEPTED / NOT VERIFIED
UNVERIFIED                      -> COMPLETION NOT CLAIMED
FAILED                          -> NO VERIFIED OUTCOME
COMPLETED after read-back       -> VERIFIED EXTERNAL STATE
```

The `Proof at a glance` card only renders live provenance when the loaded bundle identifies `T3N_TESTNET`, contains a full public 40-character commit SHA and non-empty network/contract metadata. `T3N LIVE / READY` additionally requires `protectedRemediationReady` and zero evidence failures. `NOT_RUN` remains explicit and is never promoted to proof. Proposal and Executor DID separation, effective delegation and Agent Card registration are separate facts. When live evidence is absent or returns 404, the Executive Demo shows `Live evidence not loaded/generated`, does not retry indefinitely and does not invent PASS, LIVE, source commit or verified completion.

Submission capture keeps the existing full-page technical screenshots and adds viewport-scoped 1440×900 executive frames without mocked success:

```text
01-executive-risk.png
02-executive-deny.png
03-executive-human-authorization.png
04-executive-verified-outcome.png       # only after real independent read-back
04-executive-not-verified-yet.png       # honest alternative when remediation is not run
05-executive-proof.png
```

The same capture still requires T3N testnet evidence, zero FAIL, a CLEAN source tree, three distinct DIDs, live AI minimum-remediation PASS and the existing secret-leak detector before it writes metadata. The executive frames do not replace the Evidence Center or its full technical captures.

## Business Outcome reading contract

The Protection flow places a **Business Outcome** summary before the detailed scenario/prompt/proposal panels so a judge can understand the enterprise result without reading implementation metadata first. This is a presentation layer over the existing runtime state, not a second source of authority or a second remediation state machine.

Scenario metadata defines only four static presentation facts: **Business risk**, **Protected asset**, **Business outcome** and **Success definition**. Everything that can change at runtime is derived from existing API state: incident severity, agent action/resource/destination, requested field/private-reference counts, T3N decision/reason, allowed/redacted field-name counts, authorization state, policy-allowed destination, approved destination, external execution state, verification attempts and verified final state.

The panel follows strict claim semantics:

```text
No observation                 -> Not yet observed
DENY                           -> proposal blocked; no successful remediation claim
REDACT                         -> smaller data scope required
ALLOW                          -> may continue; not human authorization or execution
REMEDIATION_AUTHORIZED         -> exact action/destination authorized; execution not implied
PENDING_VERIFICATION           -> accepted; completion not proven
UNVERIFIED / FAILED            -> no successful outcome claim
COMPLETED after read-back      -> action-specific verified final state may be shown
```

A completed credential revocation may show `REVOKED — VERIFIED`. A completed security notification may show `DELIVERED — VERIFIED` only when independent read-back also confirms `recipient_resolved=true`.

The only business-facing timing values are measured from timestamps already returned by the runtime:

```text
Time to policy decision = decision.evaluatedAt - action.createdAt
Time to verified outcome = remediation.completedAt - action.createdAt
                           only when remediation.state == COMPLETED
                           and completedAt is present and valid
```

Display rounding is deterministic: below one second use integer milliseconds; one through sixty seconds use seconds with one decimal; longer durations use minutes plus seconds. No money saved, avoided breach cost, risk-reduction percentage, SLA or ROI is calculated because those inputs do not exist in the product.

Business Outcome intentionally continues to label **Requested field names**, **Policy-allowed field names** and **Policy-redacted field names** because those are the facts it projects from PolicyDecision. The separate remediation panel and evidence path provide the value-level proof: trusted synthetic values, the exact allowed subset and fields removed before protected egress. Likewise the dashboard does not invent `Authorized by`/`Authorized at` until those facts exist in the API. `Approved destination` is presented as human-approved only after persisted action state proves the authorization transition.

The judge should use the surfaces for different questions:

- **Executive Demo**: can risk, authority path, observed outcome and compact proof be understood in one viewport without triggering side effects?
- **Business Outcome**: what risk, control and observed result does the current flow demonstrate?
- **Trust Flow**: which authority owns AI proposal, policy decision, human authorization, protected execution and verification?
- **Remediation minimization panel**: which trusted synthetic normal values and logical private references are eligible for protected egress after T3N minimization?
- **Evidence**: what live/reproducible provenance supports a claim?
- **Audit Trail**: what technical sequence was recorded locally and/or reconciled to T3N Activity Log?

## Exact human-approved destination binding

Policy permission and human intent are separate authorities. `ActionProposal.host` is persisted as a canonical lowercase ASCII hostname and participates in the T3N policy decision. When the operator authorizes protected remediation, Spring signs that exact hostname as `approvedHost` in the one-time capability. The Spring→Gateway request carries the same `approved_host`, and the gateway includes it in body-equality verification together with the action, policy provenance, fields, normal-payload hash, logical private references and Protected Executor DID.

The full action URL is never copied into the capability, audit or DOM. It remains in the private T3N `security_api_url` entry. Immediately before egress, Rust validates `approved_host`, reads the private URL, extracts its current hostname and requires exact canonical equality. A mismatch returns `EXECUTION_DESTINATION_CHANGED` **before current-policy re-evaluation and before `hwp::call`**. Only after equality succeeds does the contract re-check the active policy against the same host and approved version/hash.

```text
policy allows A + B
        |
human approved A
        |
capability approvedHost=A
        |
private KV resolves B
        |
A == B ? NO
        |
EXECUTION_DESTINATION_CHANGED
        |
zero protected HTTP egress
        |
new action + evaluation + human authorization required
```

The independent verification URL may use another hostname because it performs read-back and is not the side-effect destination authorized by the operator. UI wording therefore distinguishes **Policy-allowed destination**, **Approved destination** and **Destination changed**.

## Value-level T3N data minimization

Normal field names and normal field values have different authorities. The model may request names such as `incident_id`, `credential_id`, `reason`, `severity`, `summary` or `employee_department`, but it cannot submit `normal_payload` or `normalPayload`. Spring materializes supported demonstration values from a closed server-owned synthetic table and persists that exact map with the action. Secret/credential keys and unknown keys never receive trusted values.

The human capability binds the persisted map through `normalPayloadHash`. Java and TypeScript use the same deterministic UTF-8 canonical representation: keys are canonical lowercase identifiers, sorted by ASCII lexical order, and each entry is encoded as `<keyByteLength>:<key>=<valueByteLength>:<value>\n`. The gateway recomputes SHA-256 from the request body; changing any key or value after authorization produces `CAPABILITY_BODY_MISMATCH` before T3N execution.

Inside `execute-remediation`, Rust validates the bounded trusted map, rejects forbidden secret keys and keys that were not part of the requested field set, re-reads the approved policy version/hash, evaluates the original requested field set, then constructs the outbound map only from `normal_payload ∩ allowed_fields`. Credential revocation requires `incident_id`, `credential_id` and `reason`; security notification requires `incident_id`, `severity` and `summary`. The minimized field set is evaluated again and must resolve to `ALLOW` before `hwp::call`.

```text
trusted persisted values
  incident_id          = inc-demo-001
  credential_id        = cred-demo-001
  reason               = suspected compromise
  employee_department  = finance
            |
model requests field names only
            |
T3N policy -> REDACT employee_department
            |
capability binds exact trusted payload hash
            |
Rust intersects values with allowed_fields
            |
protected HTTP body
  incident_id
  credential_id
  reason

employee_department does not leave
```

`REDACT` is therefore not merely a schema label: the protected executor serializes a different value-level egress payload when the action-specific executable minimum remains allowed. Private references remain separate. For `notify-security`, `verified_email` must be the single allowed private reference and becomes a T3N profile placeholder only inside the protected boundary; it is never copied into the normal payload.

The UI uses four distinct normal-data terms: **Requested fields**, **Allowed for egress**, **Removed before egress** and **Protected egress payload**. It separately labels **Logical private reference**, **Resolved inside T3N protected egress**, **Plaintext not returned to the application** and **Delivery verified**. Synthetic normal values may be shown because they are demonstration data; private/secret values must not be rendered.

Local regressions prove the closed server value source, cross-runtime hash vector, body-mismatch rejection, model/A2A rejection of privileged payload fields, Rust value-level intersection, Rust-only private marker mapping and textual accessibility of allowed/removed/private-resolution state. Optional live scenario `LIVE-NORMAL-PAYLOAD-MINIMIZATION` remains `NOT_RUN` until a controlled T3N testnet action/read-back endpoint executes it. It uses synthetic sentinels and accepts PASS only when read-back reports `must_egress_seen=true` and `must_not_egress_seen=false`. The sentinel strings themselves are not persisted in public evidence.

## Why this is more than PII detection

A normal PII filter answers questions such as “does this prompt contain an email address?”. T3 Privacy Guard addresses a larger authority problem:

```text
What may the agent propose?
        |
Who is the authenticated principal?
        |
Did the Tenant record a matching Member grant?
        |
Does T3N confirm effective delegation for that authenticated principal?
        |
Which policy version governs this decision?
        |
Which action/purpose/host/data are allowed?
        |
Which trusted normal values may actually leave?
        |
Which private value may be resolved, and where?
        |
Has a human authorized the exact action, destination and policy provenance?
        |
Can this exact authorization be replayed?
        |
Did the external side effect really reach the expected state?
```

A model can therefore remain useful while being structurally unable to grant itself the missing authority.

### Pre-provider privacy boundary

Free-text prompts are untrusted and users must not paste private values into them. Before a configured remote AI provider is called, the gateway applies a deliberately **high-confidence, partial** sensitive-literal guard. It blocks supported structured classes that can be detected defensibly: e-mail, CPF, checksum-valid CNPJ, strongly signalled phone numbers (E.164 or explicit phone/mobile/telefone/celular labels), public IPv4/IPv6 explicitly labelled as customer/user data, API keys/tokens, Bearer tokens, JWTs, private-key markers, labelled passwords and Luhn-valid card candidates.

The boundary is intentionally narrow. It does not block a technical IP merely because it appears in a URL/host, and it does not use broad regexes to guess names or postal addresses. It is not a semantic or exhaustive PII scanner. Passing the guard does **not** mean a prompt is `PII-free`, `safe` or certified. Rejections expose bounded categories only; matched values and offsets are never returned to the model, browser, audit or evidence surfaces.

The TypeScript gateway and Java incident-persistence boundary share a versioned conformance corpus at `privacy-conformance/sensitive-literal-corpus.json`. Tests in both runtimes consume the same positive and false-positive fixtures so overlapping privacy behavior cannot drift silently. A provider spy additionally proves that newly blocked CNPJ, phone and labelled-public-IP cases are rejected before provider execution.

## 60-second judge story

### Attack path

```text
Prompt injection
  -> real model proposes api_key + attacker.example
  -> proposal is persisted as untrusted output
  -> authenticated Proposal Agent DID is added outside the model
  -> T3N Rust/WASM loads the active versioned policy
  -> policy evaluates the request
  -> DENY + policy provenance
  -> no human authorization
  -> no protected egress
```

The important observation is not merely that a keyword was detected. The model is allowed to produce the malicious proposal, but **the model does not control the decision boundary**.

### Legitimate protected path

```text
Minimum legitimate revoke-credential OR notify-security proposal + host A
  -> Spring persists trusted synthetic normal values separately
  -> Proposal Agent session authenticated
  -> Proposal Member grant ACTIVE
  -> Proposal checkDelegation(exact evaluate-action + minimum scopes) -> authorised=true
  -> effective Proposal access ACTIVE
  -> T3N policy ALLOW or executable REDACT + exact version/hash
  -> authenticated human authorizes exact action + destination A + policy provenance
  -> Protected Executor session authenticated
  -> Executor Member grant ACTIVE
  -> Executor checkDelegation(exact execute + verify + profile scope) -> authorised=true
  -> effective Executor access ACTIVE
  -> Spring signs one-time capability bound to destination A + normalPayloadHash + Executor DID
  -> gateway validates body equality + expiry + anti-replay
  -> T3N resolves private action URL and requires actualHost == A
  -> T3N rechecks active version/hash + same host
  -> T3N builds trusted normal_payload ∩ allowed_fields and re-evaluates minimum
  -> notify-security only: Rust creates verified_email marker; T3N resolves it during egress
  -> protected execution
  -> external acknowledgement = PENDING_VERIFICATION
  -> separate read-back
  -> revoke: VERIFIED + REVOKED
     notify: VERIFIED + DELIVERED + recipient_resolved=true
  -> Spring records COMPLETED
```

No single success signal is trusted to mean more than it proves.

## Current enterprise actions and scenario catalog

| Business scenario | Action | Purpose | Allowed normal fields | Private reference | Current demo depth |
|---|---|---|---|---|---|
| Credential compromised | `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none | Policy + value-level minimization + human authorization + exact destination binding + protected execution + independent `REVOKED` read-back |
| Account takeover | `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none | Real AI proposal + real T3N policy evaluation |
| Record security incident | `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none | Real AI proposal + real T3N policy evaluation; expected no egress |
| Notify security contact | `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | exactly `verified_email` for protected execution | Policy + logical private ref + Rust-only placeholder + human authorization + protected execution + independent `DELIVERED`/resolution read-back |

The cards are not permissions. Selecting a scenario changes only local synthetic demo context and the editable prompt; it does not call an API, authorize an action or predetermine the T3N decision. Switching scenario clears prior result state before the next analysis.

The completion verifier has two closed contracts. `revoke-credential` completes only after matching `REVOKED`. `notify-security` completes only after matching `DELIVERED` and `recipient_resolved=true`. The interface exposes protected execution controls only when the actual persisted proposal satisfies one of these closed contracts. Account isolation and incident recording remain policy-evaluation scenarios without a protected side-effect executor.

## Versioned T3N operational policy

Contract `0.4.0` separates configurable operational rules from immutable security invariants. The active canonical `PolicyDocument` is stored in the private T3N KV map `privacy-guard-policy`; React, Spring Boot and the model do not supply it to an evaluation request.

The configurable document may define enabled actions, purpose, allowed hosts, normal field allowlists, supported logical private references, host requirement and whether human authorization is required. Rust/WASM still owns the non-negotiable boundary: request/schema limits, trusted normal-payload bounds, fail-closed behavior, authenticated T3N identity/delegation constraints, forbidden secret classes, the closed private-reference vocabulary and safe host validation. A KV document cannot enable API keys, passwords, tokens or private keys as outbound fields.

Every valid policy evaluation returns:

```text
policy_version
policy_hash            canonical SHA-256
requires_human_authorization
```

Publication stores immutable `version:<version>` snapshots, a `current` pointer and publication/rollback history. Publishing different canonical content under an existing version is rejected. Rollback is explicit and may reference only an already persisted snapshot. Missing, corrupt, oversized or semantically invalid policy data fails closed.

Spring persists the version/hash with the policy decision. Human authorization requires versioned provenance and a valid persisted destination for executable egress actions. The one-time remediation capability signs the same version/hash plus the canonical approved hostname and normal-payload hash; the gateway verifies body equality; T3N first requires the private execution URL hostname to equal the approved hostname and then re-reads the current private policy before egress. If policy, trusted payload or destination changed after authorization, execution is rejected and a new action/evaluation/authorization is required.

The policy hash proves which canonical rules produced a decision; it is **not** hardware attestation.

## Effective T3N delegation model

The judge should read these controls as different facts:

```text
AUTHENTICATED
  session/key identity proved

REGISTERED
  public Proposal Agent Card resolved for same DID

MEMBER GRANT ACTIVE
  Tenant-side grant record exists and its validity window is active

EFFECTIVE ACCESS ACTIVE
  authenticated principal called checkDelegation() for its fixed minimum requirements and T3N returned authorised=true
```

The runtime never derives a canonical DID from configuration or browser input. `pii_did` for `checkDelegation()` comes only from `tenantSession.getTenantDid()`. The principal performing the check is the authenticated Proposal Agent or Protected Executor client. The contract id is the resolved canonical contract id. Proposal uses only `evaluate-action` with scopes `incident_id`, `credential_id`, `reason`. Executor uses only `execute-remediation` and `verify-remediation` with scopes `incident_id`, `credential_id`, `reason`, `verified_contacts.email.value`. Wildcard function/scope requirements are rejected and observed grant restrictions are diagnostic data, not the source of the requested check surface.

Effective-state semantics:

| Member state | T3N platform verdict | Effective state | Operational? |
|---|---|---|---|
| `ACTIVE` | `authorised=true` | `ACTIVE` | eligible, subject to all other controls |
| `ACTIVE` | `authorised=false` | `DENIED` | no |
| `ACTIVE` | error/malformed/unavailable | `UNKNOWN` | no |
| `SCHEDULED` | not called | `DENIED` | no |
| `REVOKED` | not called | `DENIED` | no |
| `NOT_GRANTED` | not called | `DENIED` | no |
| `UNKNOWN` | not called | `UNKNOWN` | no |

When no effective check is attempted, `checkedFunctions` and `checkedScopes` remain empty instead of implying a platform verdict. The Proposal Agent and Protected Executor are evaluated independently. `evaluationReady` requires the Proposal side to be effective `ACTIVE`; `protectedRemediationReady` additionally requires the Executor side to be effective `ACTIVE`. Therefore policy evaluation can remain available while protected execution is blocked.

Only bounded Member-grant fields and the exact checked function/scope labels are exposed. Raw SDK objects, credentials, tokens, `satisfied`, `missing` and arbitrary response payloads are never forwarded to Spring or the browser.

## Judge quick path

```text
1. Sign in as application operator.
2. Open Executive demo first; confirm risk, observed outcome, Trust path and Proof at a glance fit the 1440x900 view and no state-changing action is present.
3. Before analysis, confirm the Executive demo says NOT YET OBSERVED; absent evidence must say Live evidence not loaded/generated rather than LIVE/PASS.
4. Switch to Protection flow. Read the product thesis and Trust Flow, then read Business Outcome before inspecting low-level metadata.
5. Expand System readiness details and confirm Tenant, Proposal Agent and Protected Executor are authenticated as separate principals.
6. Distinguish Proposal/Executor Member grant from Effective T3N access; protected remediation is operational only when Executor effective access is ACTIVE.
7. Choose Credential compromised and inspect the synthetic attack prompt.
8. Click Analyze with agent; observe the model proposal and independent T3N DENY for the unsafe exfiltration request.
9. Use Prepare safe path. This prepares/evaluates a minimum-scope revoke-credential proposal; it does not authorize or execute it.
10. Observe ALLOW/REDACT and compare Requested fields, Allowed for egress, Removed before egress, Trusted synthetic values and Protected egress payload.
11. Authorize only after the exact destination/policy provenance are visible. Approval alone must remain AUTHORIZED / NOT EXECUTED and NOT VERIFIED YET.
12. When the environment supports synthetic egress/read-back, execute credential revocation. Accept completion only after VERIFIED + REVOKED.
13. Switch to Notify security contact. Confirm the app-visible contract contains logical private ref verified_email, Plaintext in browser = NO, Plaintext in backend = NO and Resolution boundary = T3N protected execution.
14. For an executable notify-security proposal, confirm human authorization remains required and the UI never renders a raw profile marker/address.
15. Execute only in a compatible synthetic T3N profile environment. Accept Delivery verified only after independent read-back is VERIFIED + DELIVERED + recipient_resolved=true.
16. Open Manual da Tela and confirm it explains logical refs, Rust-only marker creation, plaintext visibility, action-specific required fields, human authorization, fail-closed placeholder errors and verification semantics.
17. Open Evidence. Confirm 0 FAIL, T3N_TESTNET, full Source commit, Source tree CLEAN, separate DIDs, contract/WASM/policy provenance and honest NOT_RUN boundaries.
18. Treat LIVE-PROFILE-PLACEHOLDER-RESOLUTION as proof only when it is actually PASS from a compatible testnet run; local tests/docs do not upgrade NOT_RUN.
```

## Architecture and trust boundaries

```text
Untrusted prompt
      |
      v
AI provider (proposal names only)
      |
      v
Browser / Spring Boot
      | trusted synthetic normal payload persisted separately
      | private data represented only as verified_email logical ref
      v
T3N Gateway
      |
      +--> Tenant session ----------------------+
      |                                         |
      +--> Proposal Agent session               | pii_did
      |      |                                   |
      |      +--> Member grant                  |
      |      +--> exact checkDelegation --------+
      |      +--> effective access
      |
      +--> Protected Executor session
             |
             +--> Member grant
             +--> exact checkDelegation incl. verified profile scope
             +--> effective access
      |
      v
T3N / Rust WASM policy
      | private T3N KV policy version/hash
   DENY | REDACT | ALLOW
                    |
            authenticated human
            exact approved destination
                    |
             one-time capability
       bound to policy + normalPayloadHash + private refs + destination + Executor DID
                    |
             atomic DB claim
                    |
             execute-remediation
             KV actualHost == approvedHost
             current policy re-check
             trusted payload ∩ allowed_fields
             minimized-set re-evaluation
             notify only: Rust creates profile marker
                    |
             PENDING_VERIFICATION
                    |
              verify-remediation
                    |
          VERIFIED -> COMPLETED
          otherwise -> UNVERIFIED
```

Trust model:

- **Prompt is untrusted.** It may contain instruction injection and never becomes an authorization source. A high-confidence pre-provider literal guard reduces known structured leakage but is not a complete PII scanner.
- **Scenario selection is presentation state.** It loads synthetic input and grants no authority.
- **The model is not a security boundary.** It can only call one proposal tool with a closed JSON schema.
- **Unknown or privileged model fields are rejected.** Decisions, overrides, identities, credentials, secrets, API keys, `normal_payload`/`normalPayload` values and literal `{{profile...}}` markers are rejected before T3N evaluation.
- **Trusted normal values are application-owned.** The model selects names only; Spring materializes/persists bounded synthetic values and the capability binds their canonical hash.
- **Private data is referenced, not copied.** The model/application may request `verified_email`; only Rust/WASM can convert it to the supported T3N profile marker.
- **T3N identities are server-derived.** Tenant, Proposal Agent and Protected Executor DIDs come from authenticated sessions.
- **A Member grant is necessary but not sufficient.** Runtime readiness uses the authenticated principal-side T3N `checkDelegation()` verdict for a fixed least-privilege requirement.
- **Delegation checks fail closed.** `authorised=false`, malformed verdicts or platform errors cannot become ready states; known non-active Member states do not trigger a positive effective check.
- **Rust/WASM owns immutable security invariants.** The model and KV policy cannot manufacture authority or relax forbidden-secret/identity/delegation boundaries.
- **Private T3N KV owns versioned operational rules.** Each accepted decision exposes deterministic version/hash provenance.
- **Spring Boot owns durable business authorization and execution state.** It persists logical refs, trusted synthetic normal payload, policy provenance, canonical approved destination, human authorization transition and remediation state machine.
- **Spring Boot also owns local business-audit integrity.** Sanitized audit events are chained with a backend-only HMAC key and authenticated head; broken/unverifiable integrity blocks protected local changes without rewriting history.
- **Gateway owns T3N sessions and privileged execution.** It requires service authentication and validates/consumes the one-time capability, including exact `approved_host` and `normalPayloadHash`, before execution.
- **Private KV owns remediation credentials/endpoints.** The protected credential, full action URL and verification URL are not browser inputs. The action URL hostname must still equal the operator-approved hostname at execution time.
- **T3N protected egress is the normal-payload minimization, profile-resolution and remediation boundary.** Responses are minimized before returning to application layers.
- **HTTP acceptance is not truth.** Completion is derived from an independent closed read-back, not from the original response code.
- **Business Outcome and Executive Demo are explanatory UI, not authority.** They project existing runtime state and never fabricate policy, authorization, execution, evidence or ROI.

## Authority matrix

| Question | Source of authority |
|---|---|
| Which demo context is selected? | Browser presentation state only |
| What did the user ask? | Untrusted prompt |
| What action does the model suggest? | AI proposal |
| Which normal field names are requested? | AI proposal, subject to T3N policy |
| Which normal values are eligible to be executed? | Trusted Spring application context persisted with the action; never model/A2A input |
| Which normal values actually leave? | Rust/WASM exact intersection of trusted payload and T3N `allowed_fields`, followed by minimized-set re-evaluation |
| Which Tenant identity is the authorization subject? | Authenticated Tenant session |
| Which principal proposes policy evaluation? | Authenticated Proposal Agent session |
| Which principal executes protected remediation? | Authenticated Protected Executor session |
| Does a matching grant record exist? | Tenant-side Member Delegation document |
| Is that principal effectively delegated now? | Principal-side T3N `checkDelegation()` with canonical Tenant DID + resolved contract + fixed principal-specific functions/scopes |
| Which operational rules are active? | Versioned private T3N KV policy |
| Which critical rules cannot be relaxed? | Rust/WASM invariants |
| Is action/purpose/host/data allowed? | Rust/WASM evaluation of active policy |
| Is business remediation approved? | Authenticated human operator bound to action + canonical Approved destination + policy provenance |
| Is this exact execution authorized now? | Signed one-time capability bound to Approved destination + trusted normal-payload hash + logical private refs + Protected Executor DID |
| Is the private execution URL still the authorized destination? | Rust/WASM exact equality between `approved_host` and hostname extracted from private `security_api_url` |
| May `verified_email` be resolved? | Closed Rust mapping + T3N protected boundary after policy/human authorization |
| Did credential revocation complete? | Independent read-back matching `REVOKED` + Spring state machine |
| Was security notification delivered? | Independent read-back matching `DELIVERED` and `recipient_resolved=true` + Spring state machine |
| Is the retained local business-audit history internally authentic? | Backend HMAC chain + authenticated per-incident chain head |
| What business result should the judge read? | Business Outcome projection of the above observed state; no independent authority |
| What compact presentation should the judge read? | Executive Demo projection of the same observed state/evidence; no independent authority |

## Security claims matrix

| Claim | Current status | Source of truth |
|---|---|---|
| Real configured model produces structured proposals | PROVED LOCAL | provider adapter + agent/backend tests |
| Tool schema cannot accept decision/override/DID/secret authority fields or trusted normal-payload values | PROVED LOCAL | `proposal-schema.test.ts` |
| Trusted normal values are materialized from a closed server-owned source, not model/A2A values | PROVED LOCAL | `TrustedNormalPayloadFactoryTest`, `IncidentServiceTest` |
| Java/TypeScript canonical normal-payload SHA-256 agrees and value/key mutation is rejected | PROVED LOCAL | `NormalPayloadCanonicalizerTest`, `RemediationAuthorizationSignerTest`, `remediation-authorization.test.ts` |
| Rust protected execution serializes only trusted values whose keys survive T3N minimization | PROVED LOCAL | `remediation.rs` tests |
| `notify-security` protected execution requires `incident-notification`, its three normal fields and exactly logical `verified_email` | PROVED LOCAL | Rust/Java/gateway/frontend notification tests |
| Rust alone maps `verified_email` to `{{profile.verified_contacts.email.value}}` for protected egress | PROVED LOCAL | `remediation.rs` regression tests |
| Browser, Spring and gateway contracts carry logical private ref rather than resolved recipient | PROVED LOCAL | service/API/UI tests |
| Reflected upstream recipient/body data are not returned and unsafe operation ids are discarded | PROVED LOCAL | `remediation.rs` response-minimization tests |
| Notification completion requires independent `DELIVERED` plus `recipient_resolved=true` | PROVED LOCAL | Rust/Java/gateway/frontend verification tests |
| REDACT removes an actual normal value before protected HTTP egress | PROVED LOCAL; LIVE OPTIONAL | `remediation.rs`, `RemediationPanel.test.tsx`; `LIVE-NORMAL-PAYLOAD-MINIMIZATION` when executed |
| Controlled live payload-minimization sentinel proof | NOT CLAIMED until matching live run | `LIVE-NORMAL-PAYLOAD-MINIMIZATION` |
| High-confidence prompt literals are blocked before provider execution for supported classes, with shared Java/TypeScript conformance fixtures | PROVED LOCAL | prompt/privacy tests + shared corpus |
| Prompt guard is partial/non-semantic and does not certify accepted text as PII-free | PROVED LOCAL | frontend copy/tests + Manual da Tela |
| Four enterprise presets map to existing policy actions without authorizing them | PROVED LOCAL | `scenarioDefinitions.ts` + catalog tests |
| Business Outcome keeps DENY/REDACT/ALLOW/authorization/PENDING_VERIFICATION/COMPLETED semantically distinct | PROVED LOCAL | `BusinessOutcomeSummary.test.tsx` |
| Executive Demo projects existing dashboard runtime state without protected controls | PROVED LOCAL | Executive Demo tests |
| Tenant DID derives from authenticated T3N session | PROVED LOCAL | gateway session code/tests |
| Proposal Agent and Protected Executor use separate authenticated credentials/DIDs | PROVED LOCAL | session separation + status tests |
| Member-grant validity windows fail closed | PROVED LOCAL | `delegation-service.test.ts` |
| Effective access requires authenticated principal-side `checkDelegation()` only for an active Member grant | PROVED LOCAL | `delegation-service.test.ts` |
| Proposal and Executor checks use independent fixed least-privilege functions/scopes; Executor includes profile scope | PROVED LOCAL | `delegation-service.test.ts` |
| `pii_did` for the delegation check is authenticated Tenant DID | PROVED LOCAL | `delegation-service.test.ts` |
| `authorised=false` becomes `DENIED` and cannot become operational readiness | PROVED LOCAL | gateway/backend/frontend tests |
| Canonical policy hashing is deterministic and stale provenance fails closed | PROVED LOCAL | policy/remediation tests |
| Remediation capability binds exact policy version/hash, destination, payload hash, private refs and Executor DID | PROVED LOCAL | signer/verifier + remediation tests |
| Protected execution rejects private-KV host substitution before HTTP even when alternate host is policy-allowed | PROVED LOCAL; LIVE OPTIONAL | Rust destination-binding tests; `LIVE-DESTINATION-BINDING` when executed |
| Literal profile placeholders and unknown private refs are rejected | PROVED LOCAL | proposal schema + Spring validation + Rust tests |
| Human capability binds private refs and Protected Executor DID | PROVED LOCAL | signer/verifier tests |
| Protected remediation requires service auth + signed human capability | PROVED LOCAL | gateway authorization boundary/tests |
| Concurrent requests acquire at most one local execution claim | PROVED LOCAL | pessimistic claim + concurrency tests |
| HTTP 2xx cannot directly produce `COMPLETED` | PROVED LOCAL | Rust contract + Java state-machine tests |
| `COMPLETED` requires independent action-specific read-back | PROVED LOCAL | Rust/Java verification tests |
| Timeout/ambiguous ACK does not automatically re-execute | PROVED LOCAL | `IncidentServiceTest` |
| New local audit events form a monotonic HMAC-SHA-256 chain with authenticated tail head | PROVED LOCAL | audit integrity tests |
| Local HMAC audit is immutable/tamper-proof or detects full DB+key/backend compromise | NOT CLAIMED | outside DB-only threat model |
| Real model attack -> T3N DENY on live testnet | NOT CLAIMED | only after matching public capture/evidence run |
| T3N profile placeholder resolves verified email on live testnet | NOT RUN | `LIVE-PROFILE-PLACEHOLDER-RESOLUTION`; requires compatible synthetic profile/user context + real bound v2 human proof |
| Verified external credential revocation on live testnet | NOT CLAIMED | only after execute + independent `REVOKED` verify scenario passes |
| Verified external security notification on live testnet | NOT CLAIMED | only after profile-placeholder scenario reaches `VERIFIED`, `DELIVERED`, `recipient_resolved=true` |
| Human-approved A remains authoritative after KV changes to policy-allowed B on live testnet | NOT CLAIMED until matching live run | `LIVE-DESTINATION-BINDING` |
| Hardware attestation for this execution | NOT CLAIMED | no explicit attestation artifact yet |

## Real AI tool boundary

The forced tool shape is:

```json
{
  "action": "string",
  "resource": "string",
  "purpose": "string",
  "host": "string|null",
  "fields": ["string"],
  "private_refs": ["verified_email"]
}
```

`private_refs` contains domain-level categories only. The model cannot submit `{{profile...}}`, `profile.*`, a private value, a new private namespace, `normal_payload`/`normalPayload` or policy configuration. Provider failure, invalid JSON, missing/multiple tool calls, extra keys or unsafe authority fields fail closed.

The pre-provider guard is a separate defense-in-depth boundary from the tool schema. A matched supported literal is rejected before `provider.propose(...)` and the rejection contains categories only. The absence of a match is not an authorization decision and is not evidence that arbitrary free text contains no PII.

## Structural private-data flow

```text
Agent request: verified_email
        |
        v
Spring/H2 stores: verified_email + canonical approved destination
        |
        v
T3N policy checks notify-security + incident-notification + host + private ref
        |
        v
Human authorization capability signs privateRefsHash + approvedHost + policy provenance
        |
        v
Gateway verifies exact private_refs + approved_host + policy version/hash
        |
        v
Rust/WASM requires private KV actualHost == approvedHost
        |
        v
Rust/WASM maps verified_email
        |
        v
{{profile.verified_contacts.email.value}}
        |
        v
T3N resolves only in protected egress
        |
        v
External security service receives intended value
        |
        v
Contract returns bounded PENDING_VERIFICATION metadata
        |
        v
Independent read-back: DELIVERED + recipient_resolved=true
```

For a private value obtained through this supported logical-reference flow, plaintext visibility contract is:

- AI/model: **NO**
- React/browser: **NO**
- Spring Boot/H2: **NO**
- gateway API/logical request: **NO**
- business audit/evidence: **NO**
- T3N protected egress: **YES**, transiently for placeholder resolution
- intended external service: **YES**, because it is the authorized recipient

This visibility contract does not make a blanket claim about arbitrary user-supplied prompt text. Users must not paste private values into prompts; the high-confidence pre-provider guard is partial and deliberately does not claim semantic/exhaustive PII coverage.

If the profile field is unavailable, user context is missing, placeholder is denied, delegation is not effectively authorized, destination host differs from Approved destination, destination is not policy-authorized or policy provenance no longer matches, execution fails closed. Error text never returns resolved value or private URL. The execution response discards arbitrary upstream body/debug/recipient data and accepts `operation_id` only when it matches the bounded opaque identifier grammar.

## Verified remediation flow

```text
T3N TEE ALLOW/REDACT for supported protected action + host A
      | exact policy version/hash + trusted normal-payload subset
Authenticated operator authorizes
      | same policy provenance + exact Approved destination A + private refs + Executor DID
Spring checks persisted action + executable minimum
      |
HMAC capability binds fields + normalPayloadHash + private refs + approvedHost + policy provenance + Executor DID
      |
Atomic pessimistic claim creates EXECUTING
      |
Gateway verifies service token + capability + approved_host + normal payload hash equality
      |
Protected Executor effective access must be ACTIVE
      |
T3N execute-remediation reads private security_api_url
      | actualHost must equal approvedHost before HTTP
      | current policy/version/hash rechecked against same host
      | trusted payload intersected with allowed_fields and minimized set re-evaluated
      | notify only: verified_email marker created in Rust and resolved by T3N during egress
      | requestId -> Idempotency-Key
      v
PENDING_VERIFICATION + safe operation_id
      |
T3N verify-remediation (independent read-back endpoint)
      | revoke expected_state = REVOKED
      | notify expected_state = DELIVERED + recipient_resolved=true
      v
VERIFIED
      |
Spring marks COMPLETED + action REMEDIATED
```

Failure semantics:

- another caller sees the existing claim and does not initiate a second egress;
- a fresh `EXECUTING` claim is treated as in progress, not as recovery failure;
- a stale/recovered execution with no verifiable operation id becomes `UNVERIFIED`;
- `EXECUTION_DESTINATION_CHANGED` becomes a blocked `FAILED` execution with no protected HTTP call and requires a new action/evaluation/human authorization;
- normal payload key/value mutation after authorization fails capability equality before T3N execution;
- forbidden secret key, unrequested trusted key, missing action-specific required field or minimized set that is not `ALLOW` fails before protected HTTP egress;
- notify with missing/extra private ref, literal marker or private ref not allowed by policy fails before protected HTTP egress;
- execution timeout after request may have reached provider becomes `UNVERIFIED`, not retryable `FAILED`;
- missing/unsafe/mismatched operation id or request id becomes `UNVERIFIED`;
- missing/invalid/stale policy provenance blocks authorization/execution rather than silently falling back;
- verification outage, contradictory state, or notify read-back without `recipient_resolved=true` becomes `UNVERIFIED`;
- `UNVERIFIED` with a valid operation id can invoke **Verify external state**, which performs read-back only;
- reload fetches persisted remediation state through read-only endpoint and does not execute/verify anything.

`requestId` is a stable logical idempotency key. The application prevents duplicate local initiation through durable claim. It does **not** claim exactly-once or provider-level at-most-once unless the external provider explicitly honors the idempotency key.

## Terminal 3 integration findings

### Member Delegation and effective authorization

Member Delegation is treated as Tenant-side grant document. A matching `ACTIVE` record is necessary but not promoted directly to operational authority. Proposal and Executor checks are independent and use each authenticated grantee client. The check receives resolved contract, authenticated Tenant DID and fixed minimum requirement for that principal. Proposal checks only `evaluate-action` with `incident_id`, `credential_id`, `reason`; Executor checks only `execute-remediation` and `verify-remediation` with `incident_id`, `credential_id`, `reason`, `verified_contacts.email.value`. Wildcards are rejected. `authorised=false` is `DENIED`; errors/malformed verdicts are `UNKNOWN`; known non-active Member states fail closed without invoking effective check.

### Delegated `pii_did`

Every effective-delegation check and delegated execution derives `pii_did` internally from `tenantSession.getTenantDid()`. Browser, Java and LLM cannot supply or override authorization subject.

### Profile placeholders

Application never lets LLM/browser choose a raw placeholder. `verified_email` is mapped inside the TEE contract to the documented `profile.verified_contacts.email.value` marker. For protected `notify-security`, that mapping occurs only after the closed action/purpose/private-ref contract, one-time human proof, exact destination and current policy provenance have passed. T3N may then resolve the value only during protected egress. Application responses retain only bounded operation/state metadata and the boolean `recipient_resolved`; they do not return the address.

### Versioned private policy

Operational rules are provisioned to private T3N KV under immutable version snapshots and selected through `current` pointer. Canonical policy SHA-256 is carried as provenance across evaluation, authorization, evidence and protected execution. Policy rollback is explicit; hash is not described as attestation.

### Remediation destination and verification

Contract exposes separate `execute-remediation` and `verify-remediation` functions. Executor Member Delegation includes both only when required. Full action URL remains in private KV; one-time human capability contains only canonical Approved destination from proposal. `execute-remediation` compares that with hostname extracted from current private action URL before any HTTP call, then rechecks policy. Verification URL is independently configured/read from KV and may have another host because read-back is not the side effect operator authorized. Evidence orchestration derives allowed HTTPS hosts from configured action and verification endpoints and may add synthetic B host only for controlled testnet negative.

### Normal payload minimization

Model/A2A surface supplies field names only. Spring materializes bounded synthetic normal values from a closed table, persists them with action and signs deterministic `normalPayloadHash`. TypeScript verifies same canonical hash before T3N execution. Rust performs actual value-level minimization by intersecting persisted values with active policy's `allowed_fields`; it rejects forbidden secret keys and unrequested keys, requires the action-specific minimum and re-evaluates the minimized set before HTTP. Optional testnet payload evidence records only two controlled booleans proving one sentinel arrived and one redacted sentinel did not.

## Tamper-evident local business audit

Local business audit is a separate application control from Terminal 3 network provenance. New sanitized events are authenticated with versioned HMAC-SHA-256 chain scoped to incident. Canonical event input binds event and incident identifiers, monotonic local sequence, type, UTC timestamp, sanitized message, previous MAC and any persisted T3N sequence/hash/function. Separately authenticated chain-head record binds final retained sequence/MAC, making tail deletion detectable in addition to row edits, inserted rows, sequence gaps and link changes.

Append is serialized through pessimistic incident lock so concurrent writers cannot deliberately create same local sequence or fork chain. Verification runs oldest retained event to head. API returns integrity metadata separately from event content and separately from Activity Log reconciliation:

```text
Local integrity  VERIFIED / BROKEN / KEY_MISMATCH / LEGACY_UNVERIFIED
T3N provenance   MATCHED / UNMATCHED / LOCAL_ONLY / T3N_ONLY
```

`AUDIT_INTEGRITY_KEY` is backend-only and distinct from all T3N/provider/service/capability/operator credentials. `AUDIT_INTEGRITY_KEY_ID` and `AUDIT_INTEGRITY_PREVIOUS_KEYS` provide explicit versioned key rotation. Historical key material is required only while retained events signed by that key still need verification. Pre-HMAC events are `LEGACY_UNVERIFIED`; normal runtime keeps `AUDIT_INTEGRITY_ALLOW_LEGACY_BOOTSTRAP=false`, so old rows are not silently re-signed as if originally authenticated.

Claim boundary is intentionally narrow. This is **tamper-evident**, not immutable/tamper-proof storage. It targets DB/storage-only alteration when attacker lacks audit key. Runtime/backend compromise that can use key, simultaneous DB+key compromise, or restoration of older complete internally consistent database snapshot is outside claim without separate monotonic external audit anchor. HMAC verification is not hardware attestation and not T3N execution proof.

Broken/unverifiable local integrity blocks protected local changes rather than repairing or re-MACing history. Retention remains authoritative: when incident expires, application removes audit events and chain head instead of keeping `message` indefinitely to preserve verification.

## Public Agent onboarding and independent Activity provenance

Public registration and authorization are intentionally not conflated:

```text
Proposal Agent AUTHENTICATED
      |
      +--> Agent Card -> REGISTERED / NOT_REGISTERED / MISMATCH / UNAVAILABLE
      |
      +--> Member grant -> ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
                          |
                          +--> only ACTIVE -> checkDelegation
                                               |
                                               +--> authorised=true  -> Effective access ACTIVE
                                               +--> authorised=false -> Effective access DENIED
                                               +--> error/invalid    -> Effective access UNKNOWN
```

Protected Executor follows same model independently using own authenticated DID and fixed function/scope set. Generated Agent Card is derived from DID returned by authenticated Proposal Agent session, not configured/hardcoded DID. It advertises only supported `DID` service for same identity, is bounded to hosted-card size limit and rejects sensitive metadata/private-key-shaped values. Implementation does not advertise unsupported A2A/MCP services or x402 payment capability.

Operational commands:

```bash
cd t3n-gateway
npm run agent:card:verify    # read-only registry verification
npm run agent:card:publish   # explicit mutable host-card operation; may consume credits
```

Evidence Center/status surface can show observed onboarding state. Deployment manifest may contain public card URI, SHA-256 exact resolved card, verification timestamp and service names. Those fields are public discoverability provenance; hash is not permission or attestation claim.

Local business audit and T3N Activity Log are independent evidence sources. `MATCHED` requires exact T3N sequence/hash/function plus canonical actor for function: Proposal Agent for `evaluate-action`, Protected Executor for `execute-remediation` and `verify-remediation`. `LOCAL_ONLY`, `T3N_ONLY` and `UNMATCHED` preserve distinction when exact reconciliation absent. Unavailable/truncated Activity Log is never converted into fabricated network proof, and does not invalidate separately `VERIFIED` local HMAC chain.

## Persistent trust-manifest rollback boundary

Before Tenant, Proposal Agent or Protected Executor identity is authenticated, gateway verifies official signed trust manifest and reads persisted high-water mark for selected network. If floor exists, `fetchTrustedManifest(network, { minVersion })` is mandatory. All three sessions share same `TrustManifestFloorStore`, so one runtime cannot accept separate rollback histories for same network.

Floor is monotonic and network-scoped. It is written atomically to persistent `/data` storage and contains only network, accepted version and acceptance timestamp. Missing state is valid only for first bootstrap; malformed, truncated or unreadable state fails closed and is never silently reset.

For judging and evidence, claims are separate:

- **Trust anchor VERIFIED**: signed T3N manifest established cluster trust boundary used for authentication.
- **Rollback floor PERSISTED**: valid monotonic manifest-version floor durably stored and reused across restarts.
- **Trust manifest version**: observed high-water version associated with evidence bundle.
- **Policy version/hash**: exact canonical operational policy provenance; not hardware-attestation statement.
- **Local audit VERIFIED**: retained application HMAC chain and authenticated head verified with available key versions; not immutable storage or T3N attestation.
- **Hardware attestation**: not implied by states above and not claimed without separate execution-specific artifact.

## Evidence model

```text
public source revision
      | full 40-char Git SHA + CLEAN/DIRTY tree state
      v
verified T3N trust manifest
      |
      v
Tenant / Proposal Agent / Protected Executor authenticated sessions
      |
      +--> Proposal Agent Card provenance
      |
      +--> exact Member grants + independent principal-side checkDelegation
      v
WASM bytes -> SHA-256 ----+
policy doc -> SHA-256 ----+--> deployment-manifest.json
                           |      same source revision / DIDs / contract / version / hashes
                           v
                    testnet-run.json
```

Live orchestrator captures source revision before writing generated evidence files. Dirty working tree is rejected by default; explicit non-submission override records `sourceTreeClean=false` rather than hiding state. Manifest and testnet run must contain same source SHA/tree state or evidence API rejects bundle. Before scenario execution, orchestrator requires Proposal and Executor Member state plus effective state both `ACTIVE` for their fixed checks. `PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means scenario was not executed and never counts as success.

With `EVIDENCE_RUN_DESTINATION_BINDING=true`, testnet runner first proves A and B independently policy-allowed, mutates private action URL A to B, requires exact pre-HTTP destination mismatch and restores A in `finally`. Outside testnet mutation is rejected. With `EVIDENCE_RUN_EGRESS_NEGATIVES=true`, runner revokes Proposal and Executor independently, requires direct principal-side `checkDelegation()` to return `authorised=false`, exercises protected rejection where applicable, and restores known-good minimum grants in `finally`. Raw grant documents and SDK authorization objects are not persisted.

With `EVIDENCE_RUN_PAYLOAD_MINIMIZATION=true`, testnet runner executes controlled value-level minimization proof. PASS requires read-back proof that allowed synthetic sentinel was observed and redacted synthetic sentinel was not. Evidence stores only those booleans; sentinel strings remain prohibited from public bundle/log output. If flag/environment is absent, case remains `NOT_RUN`.

With `EVIDENCE_RUN_PROFILE_PLACEHOLDER=true`, the dedicated notification proof requires a compatible synthetic T3N verified-email profile/user context and `EVIDENCE_NOTIFICATION_AUTHORIZATION_PROOF`, a real v2 proof created by the authenticated-human flow and bound to the exact notification request. The runner sends only logical `verified_email`, executes the protected action and accepts PASS only after `VERIFIED + DELIVERED + recipient_resolved=true`. Public evidence stores no address, raw marker or authorization proof. If prerequisites are absent, the scenario remains `NOT_RUN`.

Live remediation contracts are strict:

```text
revoke-credential:
  PENDING_VERIFICATION -> safe operation_id -> VERIFIED + REVOKED

notify-security:
  logical verified_email only in app layers
  -> Rust-only profile marker
  -> T3N protected resolution/egress
  -> PENDING_VERIFICATION -> safe operation_id
  -> VERIFIED + DELIVERED + recipient_resolved=true
```

Anything less is not successful completion proof.

### Evidence UI and capture contract

`Evidence` area is ordered for judging: `Evidence summary` -> `Observed outcomes` -> `Technical provenance`. Summary surfaces PASS/FAIL/NOT RUN and execution context before low-level hashes. Technical provenance keeps source/build, trust/network, identities/discoverability and contract/policy metadata available through disclosures without weakening claim boundary.

Playwright submission capture does not read evidence by visual position or `.evidence-metadata > div` order. It uses stable semantic hooks for fields that are part of capture contract and accessible roles/names for user actions. Before screenshots or `capture-metadata.json`, it requires final UI states and records separate `tenantDid`, `proposalAgentDid`, `protectedExecutorDid`, plus full source commit, `CLEAN` source tree, contract id/version and WASM SHA-256. All three DIDs must be distinct and leak detector remains mandatory. Executive screenshots are viewport-scoped at exactly 1440×900 and assert the headline, Business risk, Observed outcome, Trust path and Proof at a glance are actually in that viewport before each frame is written.

Local controls:

```bash
bash scripts/run-local-evidence.sh
```

Live T3N evidence:

```bash
cd t3n-gateway
npm install
npm run evidence:live
```

Dedicated profile-placeholder proof:

```bash
EVIDENCE_RUN_PROFILE_PLACEHOLDER=true \
EVIDENCE_NOTIFICATION_AUTHORIZATION_PROOF='<runtime-only-v2-proof>' \
npm run evidence:profile-placeholder
```

When preparing egress evidence, configure `SECURITY_API_URL` and separate `SECURITY_VERIFICATION_URL`. Both are sealed into private map, and delegation host allowlist is derived from HTTPS endpoints. Optional destination-binding negative may add only explicitly configured synthetic `EVIDENCE_DESTINATION_B_URL` host. Generated metadata is leak-scanned for operator credentials, T3N keys, AI provider key, service token, capability signing key, audit-integrity key, remediation key, configured sentinel and the notification authorization proof.

## Screenshot shot list

1. **Executive Demo / initial risk** at 1440×900 showing the thesis, Business risk, `NOT YET OBSERVED`, Trust path and real Proof at a glance when live evidence exists.
2. **Executive Demo / DENY** showing `BLOCKED BEFORE PROTECTED EGRESS` and no executor/verification advancement.
3. **Executive Demo / human authorization** showing `AUTHORIZED / NOT EXECUTED` and `NOT VERIFIED YET`.
4. **Executive Demo / outcome** only after real independent read-back; otherwise capture the explicit not-verified state.
5. **Executive Demo / proof** showing source/network/contract/zero FAIL/DID separation/effective delegation.
6. Protection flow readiness with separate Tenant, Proposal and Executor identities plus Member/effective states.
7. Business Outcome initial and observed states without invented future values.
8. Credential-compromise attack proposal + T3N DENY + policy provenance.
9. Credential safe path with ALLOW/REDACT, trusted normal values and human-approved destination.
10. Credential execution/verification with `REVOKED — VERIFIED` only after read-back.
11. Notify security contact showing `Logical private reference = verified_email`, `Plaintext in browser = NO`, `Plaintext in backend = NO`, `Resolution boundary = T3N protected execution`, and no address/raw marker.
12. Notify authorization/execution state showing human authorization separately from PENDING verification.
13. Notify completed state only when UI reports `DELIVERED — VERIFIED`; if compatible live profile evidence is absent, keep `LIVE-PROFILE-PLACEHOLDER-RESOLUTION = NOT_RUN` visible.
14. Manual da Tela with notification purpose, fields, actions, permissions, fail-closed errors and verification semantics.
15. Evidence summary/outcomes/provenance with full source commit/tree, DIDs, contract/WASM/policy provenance and honest PASS/FAIL/NOT_RUN.

Never capture passwords, cookies, T3N keys, provider key, service/capability keys, audit-integrity key, remediation secret, notification authorization proof, resolved profile PII, `.env` or raw logs.

## Demo video storyboard

```text
0–12s    Executive Demo initial: thesis + Business risk + NOT YET OBSERVED + proof
12–30s   Protection flow: System readiness details + separate identities/delegation
30–52s   Credential compromised -> Analyze -> malicious proposal -> T3N DENY
52–64s   Executive Demo DENY: blocked before egress; executor/verify not advanced
64–92s   Prepare safe path -> ALLOW/REDACT + minimization + policy provenance
92–108s  Human authorization -> AUTHORIZED / NOT EXECUTED / NOT VERIFIED YET
108–135s If enabled: Execute -> PENDING_VERIFICATION -> independent Verify -> COMPLETED
135–150s Notify security: logical verified_email -> protected resolution boundary -> DELIVERED only if real read-back exists
150–168s Executive Demo Proof at a glance: source/network/contract/zero FAIL/DID separation
168–180s Open technical Evidence: summary -> outcomes -> provenance + honest NOT RUN
```

## UX and claim wording rules

Submission leads with user/business meaning, then exposes technical proof. Technical labels remain precise.

- **Executive Demo**: read-only one-viewport projection of existing runtime/evidence state; never a second authorization, execution or evidence engine;
- **T3N LIVE / READY**: protected-remediation readiness plus valid T3N testnet evidence with zero FAIL; not hardware attestation or proof that NOT RUN scenarios executed;
- **Live evidence not loaded/generated**: no valid evidence bundle is currently available; do not infer source commit, PASS or LIVE state;
- **enterprise scenario**: synthetic demonstration context and prompt preset, never a permission or policy decision;
- **Business Outcome**: read-only projection of observed runtime state for enterprise comprehension; not a second policy, authorization or execution engine;
- **Not yet observed**: underlying runtime fact has not been observed and must not be predicted;
- **Not verified yet / NOT VERIFIED**: no independently verified final state is available;
- **Time to policy decision**: `evaluatedAt - action.createdAt`; no synthetic estimate;
- **Time to verified outcome**: `completedAt - action.createdAt` only after `COMPLETED`;
- **agent proposal**: model-produced structured request, not authorization;
- **Requested fields**: field names selected by untrusted proposal; not values and not authority by themselves;
- **Allowed for egress**: normal field keys allowed by active T3N policy for execution being constructed;
- **Removed before egress**: requested keys excluded by minimization and not serialized into protected HTTP body;
- **Protected egress payload**: bounded trusted synthetic normal values after T3N minimization, never a model-supplied payload;
- **logical private reference**: category such as `verified_email`, never the private value;
- **Resolved inside T3N protected egress**: supported private marker is created only by Rust/WASM and resolution happens only inside the protected execution boundary;
- **Plaintext not returned to the application**: browser, Spring, gateway response, audit and public evidence do not receive the resolved recipient;
- **Delivery verified**: only after independent notification read-back returns `VERIFIED`, `DELIVERED` and `recipient_resolved=true`;
- **pre-provider privacy guard**: high-confidence, partial control for explicitly supported structured literals; not semantic/exhaustive PII scanner;
- **authenticated**: T3N session proved principal identity and yielded canonical DID;
- **registered**: public Proposal Agent Card resolved for same DID; not authorization;
- **Member grant**: Tenant-side grant record; necessary but not sufficient;
- **effective access**: `ACTIVE` only when Member grant is active and T3N returns `authorised=true`; `DENIED`/`UNKNOWN` remain non-operational;
- **Policy-allowed destination**: hostname permitted by active policy; not human intent by itself;
- **Approved destination**: exact canonical hostname bound to human authorization/capability;
- **Destination changed**: private action configuration now resolves to another hostname; execution blocked and new action/evaluation/authorization required;
- **human authorized**: business authorization persisted for exact action, Approved destination, policy provenance, trusted normal-payload hash, private refs and Protected Executor DID;
- **accepted / pending verification**: execution endpoint acknowledged operation; final state is not yet proven;
- **verified**: independent read-back matched the closed action-specific completion contract;
- **completed**: Spring persisted completion only after verified read-back;
- **unverified**: outcome ambiguous/not confirmed and no automatic re-execution occurs;
- **proved live**: matching live evidence/capture exists.

Do not say “Verified source” solely because a Git SHA/tree state is present, “Member grant ACTIVE = authorized”, “registered = authorized”, “Agent Card = attestation”, “policy allows B so the human approved B”, “field name REDACT proves value removed from egress”, “money saved”, “breach avoided”, “risk reduced by X%”, “ROI”, “local audit is immutable/tamper-proof”, “guarantees GDPR compliance”, “hardware verified”, “exactly once”, “at most once”, “profile resolution proved live” while the scenario is `NOT_RUN`, “all four scenarios execute end-to-end”, “prompt is PII-free because it passed guard” or “completed from HTTP 2xx” without corresponding evidence/contract.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new Tenant, Proposal Agent and Protected Executor credentials, operator credentials, provider key, service/capability keys, audit-integrity key and persistent gateway `/data`. Existing private keys are not transferred through GitHub/UI. Profile-backed live evidence must use a dedicated test profile with synthetic data.

This file is the repository source of truth for the public submission narrative and handover model.

## Human authorization provenance and privacy boundary

Human approval is sourced only from the authenticated Spring operator session. The authorize endpoint does not accept an approver identity from the browser. Spring persists the canonical application principal and timestamp on the action, writes a sanitized `REMEDIATION_AUTHORIZED` audit event covered by the existing HMAC chain and returns `Authorized by`/`Authorized at` only to the authenticated application UI. A same-principal retry preserves the original approval; a different principal cannot overwrite it.

The capability does not forward the username. Instead it binds `operatorPrincipalHash = SHA-256(UTF8(canonicalPrincipal))` and the persisted authorization timestamp together with action/decision/request identifiers, policy provenance, approved destination, requested fields, trusted normal-payload hash, private-reference hash and Protected Executor DID. The gateway validates both provenance fields and exact body equality before any T3N execution. Missing, malformed, future or mismatched approval provenance fails closed.

This provenance is deliberately local/private. Username, e-mail and operator hash are not Agent Card fields, are not emitted into public evidence and are not claimed as T3N Activity Log identity. Legacy `REMEDIATION_AUTHORIZED` rows without persisted principal/timestamp remain blocked and visible as `REAUTHORIZATION REQUIRED`; no identity is inferred retroactively. Completed legacy remediation cannot be rebound to a later operator.

For the judge, a human-authorization screenshot is valid only when the UI shows the persisted `Authorized by` and `Authorized at` values for the current action. `REAUTHORIZATION REQUIRED` is a blocked state, not evidence that the old authorization has been attributed to the current operator.

## Enterprise human separation of duties

The human application boundary is separate from the Tenant/Proposal Agent/Protected Executor T3N identities. Spring Security now exposes four semantic authorities and enforces them server-side before business mutations:

```text
ANALYST   -> create incidents, analyze, propose and evaluate
APPROVER  -> authorize remediation
EXECUTOR  -> execute and verify protected remediation
AUDITOR   -> read operational/audit/evidence state only
```

`ENTERPRISE_SOD_ENABLED=true` requires all four role-specific username/password pairs and four distinct usernames. Missing values, documentation placeholders or duplicated principals fail startup. The current deployment uses configured local application principals; this is **not** presented as an external corporate IdP/OIDC integration.

When enterprise SoD is disabled, the existing `OPERATOR_USERNAME/PASSWORD` receives all four semantic authorities so the local challenge/demo path remains backward compatible. The session explicitly reports `enterpriseSeparationOfDuties=false`, and the UI labels the resulting control state `LOCAL / DEMO MODE`; it must not be used as evidence of enterprise human segregation.

The browser receives only the effective authority names for presentation. It may hide or explain unavailable actions, but Spring Security remains the authorization source of truth and returns `403` before business mutation for an insufficient authority. `AUDITOR` has no business mutation path. Read-only incident, decision, remediation, audit, trace and evidence state remains visible to authenticated human authorities so an APPROVER or EXECUTOR can review the context required for its own step without receiving another mutation authority.

Enterprise remediation adds a second server-side invariant after the role check:

```text
canonical principal that authorized the action
!=
canonical principal that executes or verifies the action
```

The comparison is by authenticated principal, so a single account with multiple roles cannot bypass separation of duties. The execution claim persists `executionPrincipal` from the authenticated Spring `SecurityContext`; that value never comes from an HTTP request body. Existing execution rows without an executor principal remain legacy/unproven rather than being relabelled compliant. Retries preserve the original persisted execution provenance.

The remediation UI therefore treats these as different facts: `Authorized by`, `Execution principal` and `Separation of duties`. `CONFIRMED` requires two persisted non-equal principals. `NOT YET PROVEN` is used before an enterprise execution exists; a legacy row without provenance is not upgraded by inference. Human application principals are not called DIDs and are not represented as civil identity verification.

For an enterprise-mode judge/demo walkthrough, the human portion of the flow changes sessions deliberately:

```text
ANALYST   -> create/analyze/evaluate
APPROVER  -> review the persisted decision and authorize
EXECUTOR  -> sign in as a different principal, execute and verify
AUDITOR   -> review the resulting history/evidence without mutation controls
```

The original single-login quick path applies only to local/demo mode. In enterprise mode, authorizing and then trying to execute with the same principal must fail closed even if that account somehow has both application roles.

Required enterprise application-IAM variables are `ENTERPRISE_SOD_ENABLED`, `ANALYST_USERNAME`, `ANALYST_PASSWORD`, `APPROVER_USERNAME`, `APPROVER_PASSWORD`, `EXECUTOR_USERNAME`, `EXECUTOR_PASSWORD`, `AUDITOR_USERNAME` and `AUDITOR_PASSWORD`. These credentials do not replace T3N delegation, DIDs, the Protected Executor credential, policy provenance or the signed one-time execution capability.

## Measured control impact reading contract

The authenticated `GET /api/business-impact` endpoint converts persisted runtime outcomes into aggregate operational evidence without introducing a second policy, authorization, remediation or evidence engine. It exposes only counts, timing values and state totals; it does not return prompts, payload values, private values or operator usernames.

Supported observation windows are `retained`, `24h` and `7d`. The effective interval is always constrained by configured retention, and the response returns `from`, `to` and `retentionLimited` so a short retained history is never presented as complete historical coverage.

The aggregate formulas are intentionally explicit:

```text
blockedRatePct = DENY / evaluated decisions * 100

finalizedExecutions = COMPLETED + UNVERIFIED + FAILED
verifiedCompletionRatePct = COMPLETED / finalizedExecutions * 100

decisionLatency = decision.evaluatedAt - action.createdAt
verifiedOutcomeLatency = remediation.completedAt - action.createdAt
                         only for COMPLETED
```

When a denominator does not exist, the API returns `null` and the UI renders `NOT OBSERVED`; it never converts absence of evidence into `0%`. Median latency ignores impossible negative durations instead of reporting them. `PENDING_VERIFICATION` and `EXECUTING` do not enter the finalized-success denominator. `UNVERIFIED` and `FAILED` remain explicit non-success states.

Minimization metrics count `REDACT` decisions and the persisted names of redacted normal fields/private references. They do not count bytes, people, records saved or incidents prevented. Corrupt persisted minimization metadata fails instead of producing an invented count.

The full **Measured control impact** component belongs to Protection flow and supports the observation-window selector. Executive Demo receives only the compact summary needed for fast product comprehension: blocked, minimized, verified and median decision time. Both surfaces reuse the same server-calculated data; React does not maintain a competing aggregate formula.

Financial ROI is deliberately outside the runtime claim boundary. The product does not infer money saved, breach cost avoided, risk-reduction percentage, SLA compliance or compliance guarantees from these operational measurements. Those outcomes require customer-specific inputs that are not persisted by this challenge implementation.