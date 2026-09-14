# T3 Privacy Guard — Submission & Judge Guide

## Product position

**T3 Privacy Guard is an enterprise trust runtime for AI agents.** Its purpose is not to make the model itself trustworthy. Its purpose is to keep policy, identity, private-data resolution, business authorization and completion proof outside the model even when the model is manipulated.

The product thesis is intentionally simple:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

The challenge implementation applies that pattern to confidential incident response. The Rust policy recognizes four concrete operational actions: credential revocation, account isolation, incident recording and security notification. The Protection flow exposes all four as business-readable presets while preserving the strongest end-to-end execution/read-back path for credential revocation only.

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host`, normal field names and enumerated logical private-data references. It cannot provide a policy decision, DID, override, secret, trusted normal-payload values, execution capability or literal T3N profile placeholder.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM policy through authenticated T3N identities. The Tenant, Proposal Agent and Protected Executor have separate sessions and canonical DIDs. A malicious exfiltration proposal receives `DENY`. For protected credential revocation, Spring materializes trusted synthetic normal values independently from the model-selected field names. A legitimate policy result can be `ALLOW`, or `REDACT` when an unnecessary non-secret field is requested; REDACT can continue only when the required minimum survives and the minimized set is re-evaluated as `ALLOW` before HTTP.

An authenticated operator must explicitly authorize remediation. Spring emits a short-lived one-time signed capability bound to the exact action, decision, **canonical approved destination**, requested normal fields, `normalPayloadHash`, logical private references, Protected Executor DID and policy provenance.

Delegation is also split into two proofs. A **Member grant** is the Tenant-side record that names the grantee, contract, functions, scopes, hosts and validity window. It proves that a matching grant document exists, but it does not by itself prove that the authenticated principal is effectively authorized at that moment. Only when the matching Member grant is `ACTIVE` does the gateway call T3N `checkDelegation()` through that authenticated Proposal Agent or Protected Executor client. Proposal checks the fixed minimum requirement `evaluate-action`; Executor independently checks `execute-remediation` plus `verify-remediation`; both use only scopes `incident_id`, `credential_id`, `reason` and reject wildcard requirements. Only `authorised=true` produces **effective access `ACTIVE`**. `authorised=false` produces `DENIED`; transport, parsing or malformed verdicts produce `UNKNOWN`. Known non-active Member states fail closed without issuing a potentially misleading positive platform check.

For private profile data, the application carries only a category such as `verified_email`. The Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`; the real value can be resolved only by T3N during protected egress and is not returned to React, Java, the model or gateway responses.

Protected credential revocation is fail-safe under retries. Spring creates a persistent atomic claim before egress. The TEE sends `requestId` as the stable idempotency key, but a 2xx only produces `PENDING_VERIFICATION`. A distinct T3N `verify-remediation` read-back must observe the matching `operation_id` and the closed expected state `REVOKED` before the business state becomes `COMPLETED`. Ambiguous outcomes become `UNVERIFIED`; they may be re-verified but are never automatically executed again.

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
COMPLETED after read-back      -> verified final state may be shown
```

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
- **Remediation minimization panel**: which trusted synthetic normal values are eligible for protected egress after T3N minimization?
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

Normal field names and normal field values have different authorities. The model may request names such as `incident_id`, `credential_id`, `reason` or `employee_department`, but it cannot submit `normal_payload` or `normalPayload`. Spring materializes supported demonstration values from a closed server-owned synthetic table and persists that exact map with the action. Secret/credential keys and unknown keys never receive trusted values.

The human capability binds the persisted map through `normalPayloadHash`. Java and TypeScript use the same deterministic UTF-8 canonical representation: keys are canonical lowercase identifiers, sorted by ASCII lexical order, and each entry is encoded as `<keyByteLength>:<key>=<valueByteLength>:<value>\n`. The gateway recomputes SHA-256 from the request body; changing any key or value after authorization produces `CAPABILITY_BODY_MISMATCH` before T3N execution.

Inside `execute-remediation`, Rust validates the bounded trusted map, rejects forbidden secret keys and keys that were not part of the requested field set, re-reads the approved policy version/hash, evaluates the original requested field set, then constructs the outbound map only from `normal_payload ∩ allowed_fields`. For credential revocation, `incident_id`, `credential_id` and `reason` must remain allowed and present. The minimized field set is evaluated again and must resolve to `ALLOW` before `hwp::call`.

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

This means `REDACT` is not merely a schema label in the protected credential-revocation executor: it produces a different serialized value-level egress payload when the executable minimum remains allowed. Private references remain separate; `verified_email` still becomes a T3N profile placeholder only inside the protected boundary and is never copied into the normal payload.

The UI uses four distinct terms: **Requested fields**, **Allowed for egress**, **Removed before egress** and **Protected egress payload**. Synthetic normal values may be shown because they are demonstration data; private/secret values must not be rendered.

Local regressions prove the closed server value source, cross-runtime hash vector, body-mismatch rejection, model/A2A rejection of privileged payload fields, Rust value-level intersection and textual accessibility of allowed/removed state. Optional live scenario `LIVE-NORMAL-PAYLOAD-MINIMIZATION` remains `NOT_RUN` until a controlled T3N testnet action/read-back endpoint executes it. It uses synthetic sentinels and accepts PASS only when read-back reports `must_egress_seen=true` and `must_not_egress_seen=false`. The sentinel strings themselves are not persisted in public evidence.

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

### Legitimate path

```text
Minimum legitimate credential-revocation proposal + host A
  -> Spring persists trusted synthetic normal values separately
  -> Proposal Agent session authenticated
  -> Proposal Member grant ACTIVE
  -> Proposal checkDelegation(exact evaluate-action + minimum scopes) -> authorised=true
  -> effective Proposal access ACTIVE
  -> T3N policy ALLOW or executable REDACT + exact version/hash
  -> authenticated human authorizes exact action + destination A + policy provenance
  -> Protected Executor session authenticated
  -> Executor Member grant ACTIVE
  -> Executor checkDelegation(exact execute + verify + minimum scopes) -> authorised=true
  -> effective Executor access ACTIVE
  -> Spring signs one-time capability bound to destination A + normalPayloadHash + Executor DID
  -> gateway validates body equality + expiry + anti-replay
  -> T3N resolves private action URL and requires actualHost == A
  -> T3N rechecks active version/hash + same host
  -> T3N builds trusted normal_payload ∩ allowed_fields and re-evaluates minimum
  -> protected execution
  -> external acknowledgement = PENDING_VERIFICATION
  -> separate read-back
  -> VERIFIED REVOKED
  -> Spring records COMPLETED
```

No single success signal is trusted to mean more than it proves.

## Current enterprise actions and scenario catalog

| Business scenario | Action | Purpose | Allowed normal fields | Private reference | Current demo depth |
|---|---|---|---|---|---|
| Credential compromised | `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none | Policy + value-level minimization + human authorization + exact destination binding + protected execution + independent `REVOKED` read-back |
| Account takeover | `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none | Real AI proposal + real T3N policy evaluation |
| Record security incident | `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none | Real AI proposal + real T3N policy evaluation; expected no egress |
| Notify security contact | `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `verified_email` allowed | Real AI proposal + real T3N policy evaluation with logical private reference |

The cards are not permissions. Selecting a scenario changes only local synthetic demo context and the editable prompt; it does not call an API, authorize an action or predetermine the T3N decision. Switching scenario clears prior result state before the next analysis.

The current completion verifier understands the closed state `REVOKED`. For that reason, the interface exposes protected execution controls only for an actual `revoke-credential` proposal. It does not pretend that account isolation, incident recording or security notification already have a matching protected executor and completion verifier.

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
  public Proposal Agent Card resolved for the same DID

MEMBER GRANT ACTIVE
  Tenant-side grant record exists and its validity window is active

EFFECTIVE ACCESS ACTIVE
  authenticated principal called checkDelegation() for its fixed minimum requirements and T3N returned authorised=true
```

The runtime never derives a canonical DID from configuration or browser input. `pii_did` for `checkDelegation()` comes only from `tenantSession.getTenantDid()`. The principal performing the check is the authenticated Proposal Agent or Protected Executor client. The contract id is the resolved canonical contract id. The authorization request is fixed by principal: Proposal uses only `evaluate-action`; Executor uses only `execute-remediation` and `verify-remediation`; both use only `incident_id`, `credential_id`, `reason`. Wildcard function/scope requirements are rejected and observed grant restrictions are diagnostic data, not the source of the requested check surface.

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
2. Open Executive demo first when presenting: confirm risk, observed outcome, Trust path and Proof at a glance fit the 1440x900 view and no state-changing action is present.
3. Before analysis, confirm the Executive demo says NOT YET OBSERVED; absent evidence must say Live evidence not loaded/generated rather than LIVE/PASS.
4. Switch to Protection flow. Read the product thesis and Trust Flow, then read Business Outcome before inspecting low-level metadata.
5. In Business Outcome confirm the selected scenario's Business risk, Protected asset and Success definition; runtime facts must remain Not yet observed until analysis occurs.
6. Confirm the top readiness badge reports the current T3N control-plane state.
7. Expand System readiness details and confirm Tenant, Proposal Agent and Protected Executor are authenticated as separate principals.
8. Distinguish Proposal/Executor Member grant from Effective T3N access; Proposal evaluation is ready only with Proposal effective ACTIVE, and protected remediation is operational only when Executor effective access is also ACTIVE.
9. In Protection flow, choose Credential compromised and inspect the synthetic attack prompt.
10. Click Analyze with agent and inspect the real model proposal.
11. Read Business Outcome again: Threat observed must show actual action/resource/destination/counts; T3N control outcome must show the observed decision/reason and measured policy-decision time.
12. Observe independent T3N TEE DENY, attacker.example and exact policy version/hash; no protected execution is available.
13. Return to Executive demo and confirm DENY becomes BLOCKED BEFORE PROTECTED EGRESS while Executor remains NOT EXECUTED and Verify remains waiting.
14. Use Prepare safe path. This prepares/evaluates a minimum-scope revoke-credential proposal; it does not authorize or execute it.
15. Observe T3N ALLOW/REDACT. Business Outcome continues to report field-name counts; use the remediation panel to compare Requested fields, Allowed for egress, Removed before egress, Trusted synthetic values and Protected egress payload.
16. Before authorization, confirm Business Outcome says Human authorization = REQUIRED and Approved destination = Not authorized yet; the remediation panel may show the candidate/policy-evaluated destination separately.
17. Click Authorize credential revocation only after ALLOW or executable REDACT for that displayed destination; changing the protected destination requires a new action/evaluation/authorization.
18. Return to Executive demo and confirm AUTHORIZED / NOT EXECUTED plus NOT VERIFIED YET; authorization alone must not create a verified outcome.
19. When the environment supports synthetic egress/read-back, return to Protection flow, click Execute protected credential revocation and use Verify external state if verification remains pending.
20. While state is PENDING_VERIFICATION, confirm Business Outcome says accepted/verification pending and Final state = NOT VERIFIED.
21. Accept a successful business outcome only when Remediation execution and verification show Verification = VERIFIED and Final state = COMPLETED; Executive demo may then show VERIFIED EXTERNAL STATE and Business Outcome may show REVOKED — VERIFIED.
22. Inspect Local audit integrity separately from T3N provenance; use a local trail as proof only when its HMAC state is VERIFIED.
23. Open Evidence. Read Evidence summary first, then Observed outcomes, then expand Technical provenance.
24. Confirm 0 FAIL, T3N_TESTNET, full Source commit, Source tree CLEAN, separate Tenant/Proposal Agent/Protected Executor DIDs, Contract version/id, WASM SHA-256, policy provenance and honest NOT RUN boundaries.
25. If `LIVE-DESTINATION-BINDING` ran, accept PASS only when A and B were both policy-allowed yet the contract reported BLOCKED_BEFORE_HTTP for B after A was approved.
26. If `LIVE-NORMAL-PAYLOAD-MINIMIZATION` ran, accept PASS only when read-back reports must_egress_seen=true and must_not_egress_seen=false without exposing either sentinel value.
27. Optionally inspect Account takeover, Record security incident and Notify security contact; preset selection grants no authority and verified_email remains a logical reference rather than plaintext.
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
             +--> exact checkDelegation
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
       bound to policy + normalPayloadHash + destination + Executor DID
                    |
             atomic DB claim
                    |
             execute-remediation
             KV actualHost == approvedHost
             current policy re-check
             trusted payload ∩ allowed_fields
             minimized-set re-evaluation
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
- **Private data is referenced, not copied.** The model/application may request `verified_email`; only Rust/WASM can convert it to the official T3N profile marker.
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
- **Business Outcome is explanatory UI, not authority.** It derives observed facts from existing runtime state and never fabricates future state, ROI or a second decision path.
- **Executive Demo is explanatory UI, not authority.** It projects the same runtime state into a one-viewport narrative and has no protected operation controls.

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
| Is this exact execution authorized now? | Signed one-time capability bound to Approved destination + trusted normal-payload hash + Protected Executor DID |
| Is the private execution URL still the authorized destination? | Rust/WASM exact equality between `approved_host` and hostname extracted from private `security_api_url` |
| May a private value be resolved? | Closed Rust mapping + T3N protected boundary |
| Did the side effect complete? | Independent read-back + Spring state machine |
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
| REDACT removes an actual normal value before protected HTTP egress | PROVED LOCAL; LIVE OPTIONAL | `remediation.rs`, `RemediationPanel.test.tsx`; `LIVE-NORMAL-PAYLOAD-MINIMIZATION` when executed |
| Controlled live payload-minimization sentinel proof | NOT CLAIMED until matching live run | `LIVE-NORMAL-PAYLOAD-MINIMIZATION` / `L17` |
| High-confidence prompt literals are blocked before provider execution for supported classes, with shared Java/TypeScript conformance fixtures | PROVED LOCAL | `prompt-privacy-guard.test.ts`, `agent-service.test.ts`, `IncidentDataMinimizerTest`, `privacy-conformance/sensitive-literal-corpus.json` |
| Prompt guard is partial/non-semantic and does not certify accepted text as PII-free | PROVED LOCAL | `PROMPT_PRIVACY_GUARD_SCOPE`, frontend copy/tests, Manual da Tela |
| Four enterprise presets map to existing policy actions without authorizing them | PROVED LOCAL | `scenarioDefinitions.ts` + `EnterpriseScenarioCatalog.test.tsx` |
| Scenario selection does not submit the prompt automatically | PROVED LOCAL | `EnterpriseScenarioCatalog.test.tsx` + controlled prompt flow |
| Business Outcome exposes static business context plus only observed runtime facts, never invented completion/ROI | PROVED LOCAL | `BusinessOutcomeSummary.tsx`, `BusinessOutcomeSummary.test.tsx`, Manual da Tela |
| Business Outcome policy timing uses `evaluatedAt - action.createdAt` and verified-outcome timing uses `completedAt - action.createdAt` only after COMPLETED | PROVED LOCAL | `BusinessOutcomeSummary.tsx`, `BusinessOutcomeSummary.test.tsx` |
| Business Outcome keeps DENY/REDACT/ALLOW/authorization/PENDING_VERIFICATION/COMPLETED semantically distinct | PROVED LOCAL | `BusinessOutcomeSummary.test.tsx` |
| Executive Demo projects the existing dashboard runtime state without exposing Analyze/Authorize/Execute/Verify controls | PROVED LOCAL | `ExecutiveDemoView.tsx`, `ExecutiveDemoView.test.tsx`, `DashboardTabs.test.tsx` |
| Executive Demo keeps DENY/REDACT/ALLOW/authorization/PENDING_VERIFICATION/UNVERIFIED/FAILED/COMPLETED semantically distinct | PROVED LOCAL | `ExecutiveDemoView.test.tsx` |
| Executive Demo shows T3N LIVE / READY only with protected-remediation readiness, valid T3N testnet evidence and zero FAIL | PROVED LOCAL | `ExecutiveDemoView.tsx`, `ExecutiveDemoView.test.tsx` |
| Tenant DID derives from authenticated T3N session | PROVED LOCAL | gateway session code/tests |
| Proposal Agent and Protected Executor use separate authenticated credentials/DIDs | PROVED LOCAL | session separation + status tests |
| Member-grant validity windows fail closed | PROVED LOCAL | `delegation-service.test.ts` |
| Effective access requires authenticated principal-side `checkDelegation()` only for an active Member grant | PROVED LOCAL | `delegation-service.test.ts` |
| Proposal and Executor checks use independent fixed least-privilege functions/scopes with no wildcard | PROVED LOCAL | `delegation-service.test.ts` |
| `pii_did` for the delegation check is authenticated Tenant DID | PROVED LOCAL | `delegation-service.test.ts` |
| `authorised=false` becomes `DENIED` and cannot become operational readiness | PROVED LOCAL | gateway/backend/frontend tests |
| `checkDelegation()` error or malformed response becomes `UNKNOWN`, never ready | PROVED LOCAL | gateway/backend/frontend tests |
| UI separates Member grant and Effective T3N access, with evaluation readiness distinct from protected-remediation readiness | PROVED LOCAL | `SystemStatusBar.test.tsx`, `TrustFlowSummary.test.tsx` |
| Canonical policy hashing is deterministic | PROVED LOCAL | `policy-document.test.ts` |
| Reusing a version with different content is rejected | PROVED LOCAL | policy provisioner + tests |
| Missing/invalid policy fails closed | PROVED LOCAL | Rust policy tests + gateway contract path |
| Critical forbidden-secret/private-ref invariants cannot be relaxed by KV policy | PROVED LOCAL | Rust adversarial/policy tests |
| Policy version/hash propagate through decision, persistence, UI and evidence metadata | PROVED LOCAL | backend/frontend/evidence tests |
| Live evidence source revision is a full Git SHA with explicit CLEAN/DIRTY state | PROVED LOCAL | `source-revision.test.ts`, manifest/backend/frontend evidence tests |
| Remediation capability binds exact policy version/hash | PROVED LOCAL | signer/verifier + remediation tests |
| Remediation capability binds exact canonical Approved destination | PROVED LOCAL | `RemediationAuthorizationSignerTest`, gateway verifier tests, `IncidentServiceTest` |
| Protected execution rejects private-KV host substitution before HTTP even when alternate host is policy-allowed | PROVED LOCAL; LIVE OPTIONAL | Rust destination-binding tests; `LIVE-DESTINATION-BINDING` when executed on testnet |
| Protected execution rejects stale policy provenance | PROVED LOCAL | Rust/gateway remediation tests |
| Literal profile placeholders and unknown private refs are rejected | PROVED LOCAL | proposal schema + Spring validation + Rust policy tests |
| `verified_email` is current logical private reference | PROVED LOCAL | Rust policy/remediation mapping |
| Rust maps `verified_email` to `{{profile.verified_contacts.email.value}}` | PROVED LOCAL | Rust remediation regression test |
| Java/H2 persists logical refs, not plaintext profile values | PROVED LOCAL | entity/service/API model + tests |
| Human capability binds private refs and Protected Executor DID | PROVED LOCAL | signer/verifier tests |
| Reflected upstream private value is absent from contract result schema | PROVED LOCAL | Rust remediation regression test |
| Protected remediation requires service auth + signed human capability | PROVED LOCAL | gateway authorization boundary/tests |
| Concurrent requests acquire at most one local execution claim | PROVED LOCAL | pessimistic claim + concurrency tests |
| HTTP 2xx cannot directly produce `COMPLETED` | PROVED LOCAL | Rust contract + Java state-machine tests |
| `COMPLETED` requires independent read-back of matching operation/state | PROVED LOCAL | Rust/Java verification tests |
| Timeout/ambiguous ACK does not automatically re-execute | PROVED LOCAL | `IncidentServiceTest` |
| Reload reads persisted execution state without egress/reverification | PROVED LOCAL | `RemediationQueryServiceTest` + frontend API flow |
| New local audit events form a monotonic HMAC-SHA-256 chain with authenticated tail head | PROVED LOCAL | `AuditIntegrityServiceTest` |
| Direct local audit content/link/sequence/T3N-provenance tampering and retained-tail deletion are detected | PROVED LOCAL | `AuditIntegrityServiceTest`, `AuditIntegrityGuardTest` |
| Concurrent local audit appends remain one linear sequence | PROVED LOCAL | `AuditIntegrityServiceTest` concurrency case |
| Audit key rotation is explicit and old retained events verify only with configured historical key material | PROVED LOCAL | `AuditIntegrityRotationTest` |
| Legacy rows are never silently promoted to cryptographically verified history | PROVED LOCAL | `AuditIntegrityServiceTest` |
| Local HMAC audit is immutable/tamper-proof or detects full DB+key/backend compromise | NOT CLAIMED | outside DB-only threat model; no external monotonic audit anchor |
| Real model attack -> T3N DENY on live testnet | NOT CLAIMED | only after matching public capture/evidence run |
| T3N profile placeholder resolves verified email on live testnet | NOT RUN | requires compatible profile/user context and matching evidence |
| Verified external remediation on live testnet | NOT CLAIMED | only after execute + independent verify scenario passes |
| Human-approved A remains authoritative after KV changes to policy-allowed B on live testnet | NOT CLAIMED until matching live run | `LIVE-DESTINATION-BINDING` |
| Revoked Proposal/Executor delegation makes direct principal-side `checkDelegation()` return `authorised=false` and minimum grants can be restored | NOT CLAIMED until matching live run | `LIVE-REVOKED-PROPOSAL-CHECK` / `LIVE-REVOKED-EXECUTOR-CHECK` |
| Revoked Executor delegation blocks protected egress on live testnet | NOT CLAIMED | only after matching live evidence |
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
T3N policy checks action + purpose + host + private ref
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
External service receives intended value
        |
        v
Contract returns minimized operation metadata
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

If the profile field is unavailable, user context is missing, placeholder is denied, delegation is not effectively authorized, destination host differs from Approved destination, destination is not policy-authorized or policy provenance no longer matches, execution fails closed. Error text never returns resolved value or private URL.

## Verified remediation flow

```text
T3N TEE ALLOW/REDACT for revoke-credential + host A
      | exact policy version/hash + trusted normal-payload subset
Authenticated operator authorizes
      | same policy provenance + exact Approved destination A + Executor DID
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
      | requestId -> Idempotency-Key
      v
PENDING_VERIFICATION + operation_id
      |
T3N verify-remediation (independent read-back endpoint)
      | expected_state = REVOKED only
      v
VERIFIED (same operation + REVOKED)
      |
Spring marks COMPLETED + action REMEDIATED
```

Failure semantics:

- another caller sees the existing claim and does not initiate a second egress;
- a fresh `EXECUTING` claim is treated as in progress, not as recovery failure;
- a stale/recovered execution with no verifiable operation id becomes `UNVERIFIED`;
- `EXECUTION_DESTINATION_CHANGED` becomes a blocked `FAILED` execution with no protected HTTP call and requires a new action/evaluation/human authorization;
- normal payload key/value mutation after authorization fails capability equality before T3N execution;
- forbidden secret key, unrequested trusted key, missing required executable field or minimized set that is not `ALLOW` fails before protected HTTP egress;
- execution timeout after request may have reached provider becomes `UNVERIFIED`, not retryable `FAILED`;
- missing/mismatched operation id or request id becomes `UNVERIFIED`;
- missing/invalid/stale policy provenance blocks authorization/execution rather than silently falling back;
- verification outage or contradictory state becomes `UNVERIFIED`;
- `UNVERIFIED` with operation id can invoke **Verify external state**, which performs read-back only;
- reload fetches persisted remediation state through read-only endpoint and does not execute/verify anything.

`requestId` is a stable logical idempotency key. The application prevents duplicate local initiation through durable claim. It does **not** claim exactly-once or provider-level at-most-once unless external provider explicitly honors the idempotency key.

## Terminal 3 integration findings

### Member Delegation and effective authorization

Member Delegation is treated as Tenant-side grant document. A matching `ACTIVE` record is necessary but not promoted directly to operational authority. Proposal and Executor checks are independent and use each authenticated grantee client. The check receives resolved contract, authenticated Tenant DID and fixed minimum requirement for that principal: Proposal checks only `evaluate-action`; Executor checks only `execute-remediation` and `verify-remediation`; both check scopes `incident_id`, `credential_id`, `reason`. Wildcards are rejected. `authorised=false` is `DENIED`; errors/malformed verdicts are `UNKNOWN`; known non-active Member states fail closed without invoking effective check.

### Delegated `pii_did`

Every effective-delegation check and delegated execution derives `pii_did` internally from `tenantSession.getTenantDid()`. Browser, Java and LLM cannot supply or override authorization subject.

### Profile placeholders

Application never lets LLM/browser choose a raw placeholder. `verified_email` is mapped inside TEE contract to documented `profile.verified_contacts.email.value` marker, limiting public application contract to auditable domain vocabulary.

### Versioned private policy

Operational rules are provisioned to private T3N KV under immutable version snapshots and selected through `current` pointer. Canonical policy SHA-256 is carried as provenance across evaluation, authorization, evidence and protected execution. Policy rollback is explicit; hash is not described as attestation.

### Remediation destination and verification

Contract exposes separate `execute-remediation` and `verify-remediation` functions. Executor Member Delegation includes both only when required. Full action URL remains in private KV; one-time human capability contains only canonical Approved destination from proposal. `execute-remediation` compares that with hostname extracted from current private action URL before any HTTP call, then rechecks policy. Verification URL is independently configured/read from KV and may have another host because read-back is not side effect operator authorized. Evidence orchestration derives allowed HTTPS hosts from configured action and verification endpoints and may add synthetic B host only for controlled testnet negative.

### Normal payload minimization

Model/A2A surface supplies field names only. Spring materializes bounded synthetic normal values from a closed table, persists them with action and signs deterministic `normalPayloadHash`. TypeScript verifies same canonical hash before T3N execution. Rust performs actual value-level minimization by intersecting persisted values with active policy's `allowed_fields`; it rejects forbidden secret keys and unrequested keys, requires credential-revocation minimum and re-evaluates minimized set before HTTP. Optional testnet evidence records only two controlled booleans proving one sentinel arrived and one redacted sentinel did not.

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

Protected Executor follows same model independently using own authenticated DID and fixed function set. Generated Agent Card is derived from DID returned by authenticated Proposal Agent session, not configured/hardcoded DID. It advertises only supported `DID` service for same identity, is bounded to hosted-card size limit and rejects sensitive metadata/private-key-shaped values. Implementation does not advertise unsupported A2A/MCP services or x402 payment capability.

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

Live orchestrator captures source revision before writing generated evidence files. Dirty working tree is rejected by default; explicit non-submission override records `sourceTreeClean=false` rather than hiding state. Manifest and testnet run must contain same source SHA/tree state or evidence API rejects bundle. Before scenario execution, orchestrator requires Proposal and Executor Member state plus effective state both `ACTIVE` for fixed minimum checks. `PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means scenario was not executed and never counts as success. Profile-placeholder execution remains `NOT_RUN` until compatible profile/user context exists; local tests do not upgrade that claim to live proof.

With `EVIDENCE_RUN_DESTINATION_BINDING=true`, testnet runner first proves A and B independently policy-allowed, mutates private action URL A to B, requires exact pre-HTTP destination mismatch and restores A in `finally`. Outside testnet mutation is rejected. With `EVIDENCE_RUN_EGRESS_NEGATIVES=true`, runner revokes Proposal and Executor independently, requires direct principal-side `checkDelegation()` to return `authorised=false`, exercises protected rejection where applicable, and restores known-good minimum grants in `finally`. Raw grant documents and SDK authorization objects are not persisted.

With `EVIDENCE_RUN_PAYLOAD_MINIMIZATION=true`, testnet runner executes controlled value-level minimization proof. PASS requires read-back proof that allowed synthetic sentinel was observed and redacted synthetic sentinel was not. Evidence stores only those booleans; sentinel strings remain prohibited from public bundle/log output. If flag/environment is absent, case remains `NOT_RUN`.

Live remediation scenario is stricter:

```text
attack DENY + policy provenance
   -> exact Approved destination still matches private action URL
   -> execute-remediation with same policy provenance and trusted normal payload
   -> PENDING_VERIFICATION
   -> operation_id present
   -> verify-remediation VERIFIED
   -> observed_state REVOKED
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

When preparing egress evidence, configure `SECURITY_API_URL` and separate `SECURITY_VERIFICATION_URL`. Both are sealed into private map, and delegation host allowlist is derived from HTTPS endpoints. Optional destination-binding negative may add only explicitly configured synthetic `EVIDENCE_DESTINATION_B_URL` host. Generated metadata is leak-scanned for operator credentials, T3N keys, AI provider key, service token, capability signing key, audit-integrity key, remediation key and configured sentinel.

## Screenshot shot list

1. **Executive Demo / initial risk** at 1440×900 showing the thesis, Business risk, `NOT YET OBSERVED`, Trust path and real Proof at a glance when live evidence exists (`01-executive-risk.png`).
2. **Executive Demo / DENY** at 1440×900 showing `BLOCKED BEFORE PROTECTED EGRESS`, T3N policy DENY, Executor `NOT EXECUTED` and Verify waiting (`02-executive-deny.png`).
3. **Executive Demo / human authorization** at 1440×900 showing `AUTHORIZED / NOT EXECUTED`, Human `AUTHORIZED`, Executor `NOT STARTED` and Verify `NOT VERIFIED YET` (`03-executive-human-authorization.png`).
4. **Executive Demo / outcome** at 1440×900: use `04-executive-verified-outcome.png` only after independent VERIFIED/COMPLETED read-back; otherwise capture `04-executive-not-verified-yet.png` and keep the missing verification explicit.
5. **Executive Demo / proof** at 1440×900 showing commit prefix, network, contract version, zero FAIL, explicit NOT RUN count, separate Proposal/Executor identities, effective delegation and Agent Card state (`05-executive-proof.png`).
6. Product header + judge-first Trust Flow + current T3N readiness badge in the operational Protection flow.
7. **Business Outcome** immediately below top controls, showing Business risk, Protected asset, Success definition and only observed runtime state; initial/future values remain Not yet observed / Not verified yet.
8. Expanded **System readiness details** showing separate Tenant, Proposal Agent and Protected Executor identities.
9. Separate Proposal/Executor **Member grant** and **Effective T3N access** states; capture `Operational` only when protected remediation is ready, and show `Evaluation ready · execution blocked` when only Proposal is effectively authorized.
10. **Protection flow** with Credential compromised selected and statement that presets are not permissions.
11. Attack prompt + provider/model provenance + model proposal after **Analyze with agent** + `DENY` + policy version/hash, with Business Outcome showing same observed threat/control in business language.
12. `REDACT` data-minimization evidence showing Requested fields, Allowed for egress, Removed before egress, Trusted synthetic values and Protected egress payload. Business Outcome field counts remain explicitly schema-level.
13. Notify security contact selected, showing logical `verified_email` and no plaintext address/raw placeholder.
14. **Prepare safe path** result showing legitimate minimum credential-revocation proposal + `ALLOW` or executable `REDACT` + policy provenance.
15. Business Outcome before authorization showing Human authorization = REQUIRED and Approved destination = Not authorized yet.
16. **Approved destination** visible after authorization without revealing private full URL; Business Outcome and protected-remediation panel agree.
17. **Authorize credential revocation** shown separately from **Execute protected credential revocation**, bound to same version/hash, payload hash, exact destination and Protected Executor.
18. Execution/verification panel showing Authorization, Execution, Verification and Final state; use **Verify external state** for read-back-only retry when available.
19. While pending, Business Outcome remains `NOT VERIFIED`; after independent verification it may show `REVOKED — VERIFIED` plus measured time to verified outcome.
20. If captured, `Destination changed` shows new-action/re-evaluate/re-authorize guidance rather than generic outage.
21. Local audit integrity shown separately from T3N Activity Log provenance; capture `VERIFIED` only when HMAC verification actually succeeded.
22. Verified remediation screenshot only after `Verification = VERIFIED` and `Final state = COMPLETED`.
23. **Evidence** with `Evidence summary`, `Observed outcomes`, then expanded `Technical provenance`; include full Source commit, Source tree state, separate Proposal Agent/Protected Executor DIDs, T3N_TESTNET, contract/WASM/policy provenance and optional scenarios honestly PASS/FAIL/NOT RUN.

Never capture passwords, cookies, T3N keys, provider key, service/capability keys, audit-integrity key, remediation secret, resolved profile PII, `.env` or raw logs.

## Demo video storyboard

```text
0–12s    Executive Demo initial: thesis + Business risk + NOT YET OBSERVED + proof
12–30s   Protection flow: System readiness details + separate identities/delegation
30–52s   Credential compromised -> Analyze -> malicious proposal -> T3N DENY
52–64s   Executive Demo DENY: blocked before egress; executor/verify not advanced
64–92s   Prepare safe path -> ALLOW/REDACT + minimization + policy provenance
92–108s  Human authorization -> Executive Demo AUTHORIZED / NOT EXECUTED / NOT VERIFIED YET
108–135s If enabled: Execute -> PENDING_VERIFICATION -> independent Verify -> COMPLETED
135–150s Executive Demo verified outcome only when read-back actually succeeded
150–168s Executive Demo Proof at a glance: source/network/contract/zero FAIL/DID separation
168–180s Open technical Evidence: summary -> outcomes -> provenance + honest NOT RUN
```

## UX and claim wording rules

Submission leads with user/business meaning, then exposes technical proof. Technical labels remain precise.

- **Executive Demo**: read-only one-viewport projection of existing runtime/evidence state; never a second authorization, execution or evidence engine;
- **T3N LIVE / READY** in Executive Demo: protected-remediation readiness plus a valid T3N testnet evidence bundle with zero FAIL; not hardware attestation or proof that NOT RUN scenarios executed;
- **Live evidence not loaded/generated**: no valid evidence bundle is currently available to this view; do not infer source commit, PASS or LIVE state;
- **enterprise scenario**: synthetic demonstration context and prompt preset, never a permission or policy decision;
- **Business risk / Protected asset / Business outcome / Success definition**: static scenario presentation metadata, never evidence that a result occurred;
- **Business Outcome**: read-only projection of observed runtime state for enterprise comprehension; not a second policy, authorization or execution engine;
- **Not yet observed**: underlying runtime fact has not been observed and must not be predicted;
- **Not verified yet / NOT VERIFIED**: no independently verified final state is available;
- **Time to policy decision**: `evaluatedAt - action.createdAt`; no synthetic estimate;
- **Time to verified outcome**: `completedAt - action.createdAt` only after `COMPLETED`; no estimate when timestamp/state is absent;
- **agent proposal**: model-produced structured request, not authorization;
- **Requested fields**: field names selected by untrusted proposal; not values and not authority by themselves;
- **Allowed for egress**: normal field keys allowed by active T3N policy for execution being constructed;
- **Removed before egress**: requested keys excluded by minimization and not serialized into protected HTTP body;
- **Protected egress payload**: bounded trusted synthetic normal values after T3N minimization, never a model-supplied payload;
- **Business Outcome field-name counts**: schema-level observations from PolicyDecision; use remediation/evidence surface for value-level egress proof;
- **pre-provider privacy guard**: high-confidence, partial control for explicitly supported structured literals; not semantic/exhaustive PII scanner, and accepted prompt is not certified PII-free or safe;
- **authenticated**: T3N session proved principal identity and yielded canonical DID;
- **registered**: public Proposal Agent Card resolved and matched authenticated DID; not authorization;
- **Member grant**: Tenant-side grant record with grantee, contract, functions, scopes, hosts and validity window; necessary but not sufficient;
- **effective access**: runtime result of principal-specific minimum authorization requirement; `ACTIVE` only when Member grant active and T3N returns `authorised=true`, `DENIED` on explicit denial/known non-active grant, `UNKNOWN` on inconclusive validation;
- **Policy-allowed destination**: hostname belonging to set permitted by active policy; not human intent by itself;
- **Approved destination**: exact canonical hostname shown to operator and bound to human authorization/capability; present as approved only after authorization state exists;
- **Destination changed**: private action configuration now resolves to another hostname; execution blocked and new action/evaluation/authorization required;
- **human authorized**: business authorization persisted for exact action, Approved destination, policy provenance, trusted normal-payload hash and Protected Executor DID; do not invent author identity/timestamp when API does not expose them;
- **local audit integrity VERIFIED**: retained HMAC chain, sequence/linkage and authenticated head validated with configured key versions; not immutable storage, T3N provenance or hardware attestation;
- **local audit integrity BROKEN**: retained history diverged from authenticated chain/head; protected changes blocked and history not auto-repaired;
- **LEGACY_UNVERIFIED**: retained pre-HMAC events remain visible but are not presented as cryptographically authenticated history;
- **source commit**: full public Git revision captured before evidence generation; source traceability, not independent verification;
- **source tree CLEAN**: no tracked or untracked working-tree changes at capture time; reproducibility signal, not security certification;
- **source tree DIRTY**: source differed from recorded commit; disclosed explicitly and rejected for submission evidence by default;
- **policy version**: immutable operational ruleset identifier loaded from private T3N KV;
- **policy hash**: deterministic canonical SHA-256 proving policy provenance, not hardware attestation;
- **logical private reference**: category such as `verified_email`, not private value;
- **resolved by T3N at egress**: only claim for executions where T3N actually resolved placeholder;
- **accepted / pending verification**: execution endpoint acknowledged operation; final state is not yet proven;
- **verified**: independent read-back matched closed expected state;
- **completed**: Spring persisted completion only after verified read-back;
- **unverified**: outcome ambiguous/not confirmed and no automatic re-execution occurs;
- **execution proof**: short-lived server-to-gateway capability bound to exact approved request including destination and trusted normal-payload hash; not hardware attestation;
- **proved live**: matching live evidence/capture exists.

Do not say “Verified source” solely because a Git SHA/tree state is present, “Member grant ACTIVE = authorized”, “registered = authorized”, “Agent Card = attestation”, “policy allows B so the human approved B”, “field name REDACT proves value removed from egress”, “money saved”, “breach avoided”, “risk reduced by X%”, “ROI”, “local audit is immutable/tamper-proof”, “local audit VERIFIED = T3N MATCHED”, “guarantees GDPR compliance”, “hardware verified”, “exactly once”, “at most once”, “profile resolution proved live”, “all four scenarios execute end-to-end”, “prompt is PII-free because it passed guard” or “completed from HTTP 2xx” without corresponding evidence/contract.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new Tenant, Proposal Agent and Protected Executor credentials, operator credentials, provider key, service/capability keys, audit-integrity key and persistent gateway `/data`. Existing private keys are not transferred through GitHub/UI. Profile-backed live evidence must use a dedicated test profile with synthetic data.

This file is the repository source of truth for the public submission narrative and handover model.

## Human authorization provenance and privacy boundary

Human approval is sourced only from the authenticated Spring operator session. The authorize endpoint does not accept an approver identity from the browser. Spring persists the canonical application principal and timestamp on the action, writes a sanitized `REMEDIATION_AUTHORIZED` audit event covered by the existing HMAC chain and returns `Authorized by`/`Authorized at` only to the authenticated application UI. A same-principal retry preserves the original approval; a different principal cannot overwrite it.

The capability does not forward the username. Instead it binds `operatorPrincipalHash = SHA-256(UTF8(canonicalPrincipal))` and the persisted authorization timestamp together with action/decision/request identifiers, policy provenance, approved destination, requested fields, trusted normal-payload hash, private-reference hash and Protected Executor DID. The gateway validates both provenance fields and exact body equality before any T3N execution. Missing, malformed, future or mismatched approval provenance fails closed.

This provenance is deliberately local/private. Username, e-mail and operator hash are not Agent Card fields, are not emitted into public evidence and are not claimed as T3N Activity Log identity. Legacy `REMEDIATION_AUTHORIZED` rows without persisted principal/timestamp remain blocked and visible as `REAUTHORIZATION REQUIRED`; no identity is inferred retroactively. Completed legacy remediation cannot be rebound to a later operator.

For the judge, a human-authorization screenshot is valid only when the UI shows the persisted `Authorized by` and `Authorized at` values for the current action. `REAUTHORIZATION REQUIRED` is a blocked state, not evidence that the old authorization has been attributed to the current operator.
