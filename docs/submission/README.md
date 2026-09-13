# T3 Privacy Guard — Submission & Judge Guide

## Product position

**T3 Privacy Guard is an enterprise trust runtime for AI agents.** Its purpose is not to make the model itself trustworthy. Its purpose is to keep policy, identity, private-data resolution, business authorization and completion proof outside the model even when the model is manipulated.

The product thesis is intentionally simple:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

The challenge implementation applies that pattern to confidential incident response. The Rust policy recognizes four concrete operational actions: credential revocation, account isolation, incident recording and security notification. The Protection flow exposes all four as business-readable presets while preserving the strongest end-to-end execution/read-back path for credential revocation only.

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host`, normal field names and enumerated logical private-data references. It cannot provide a policy decision, DID, override, secret, execution capability or literal T3N profile placeholder.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM policy through authenticated T3N identities. The Tenant, Proposal Agent and Protected Executor have separate sessions and canonical DIDs. A malicious exfiltration proposal receives `DENY`. A minimum legitimate proposal can receive `ALLOW`, but `ALLOW` is still not execution: an authenticated operator must explicitly authorize remediation, after which Spring emits a short-lived one-time signed capability bound to the exact action, decision, **canonical approved destination**, normal fields, logical private references, Protected Executor DID and policy provenance.

Delegation is also split into two proofs. A **Member grant** is the Tenant-side record that names the grantee, contract, functions, scopes, hosts and validity window. It proves that a matching grant document exists, but it does not by itself prove that the authenticated principal is effectively authorized at that moment. Only when the matching Member grant is `ACTIVE` does the gateway call T3N `checkDelegation()` through that authenticated Proposal Agent or Protected Executor client. Proposal checks the fixed minimum requirement `evaluate-action`; Executor independently checks `execute-remediation` plus `verify-remediation`; both use only scopes `incident_id`, `credential_id`, `reason` and reject wildcard requirements. Only `authorised=true` produces **effective access `ACTIVE`**. `authorised=false` produces `DENIED`; transport, parsing or malformed verdicts produce `UNKNOWN`. Known non-active Member states fail closed without issuing a potentially misleading positive platform check.

For private profile data, the application carries only a category such as `verified_email`. The Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`; the real value can be resolved only by T3N during protected egress and is not returned to React, Java, the model or gateway responses.

Protected credential revocation is fail-safe under retries. Spring creates a persistent atomic claim before egress. The TEE sends `requestId` as the stable idempotency key, but a 2xx only produces `PENDING_VERIFICATION`. A distinct T3N `verify-remediation` read-back must observe the matching `operation_id` and the closed expected state `REVOKED` before the business state becomes `COMPLETED`. Ambiguous outcomes become `UNVERIFIED`; they may be re-verified but are never automatically executed again.

The local business audit has a separate integrity control. New sanitized events are linked in a versioned HMAC-SHA-256 chain per incident, with monotonic local sequence and an authenticated chain head. This makes DB/storage-only changes detectable when the attacker does not have the audit key. The control is deliberately described as **tamper-evident**, never immutable or tamper-proof, and remains independent from T3N Activity Log provenance.

The operational policy used by contract `0.4.0` is versioned in private T3N KV. Each decision carries the exact `policyVersion` and deterministic SHA-256 `policyHash`; critical invariants remain compiled in WASM. Missing or invalid policy fails closed. Human authorization and protected execution are bound to the same version/hash so a policy change after approval cannot silently reuse stale authority. Destination binding is an additional and stricter invariant: a policy may allow hosts A and B, but an operator approval for A cannot be reused for B.

The project reports only verifiable state: `NOT_RUN` never becomes `PASS`, simulated output is not labelled live, profile-placeholder resolution is not labelled proved live until a compatible testnet profile actually executes it, an observed Member grant is not labelled effective authority, external execution is not labelled completed from HTTP acceptance alone, local audit integrity is not labelled immutable storage, and hardware attestation is not claimed without a concrete artifact.

Each live evidence bundle records the full public Git commit SHA and whether the source tree was `CLEAN` or `DIRTY` when evidence generation began. Submission evidence fails closed on a dirty tree by default. The source revision provides reproducibility and public-code traceability; the WASM SHA-256 and policy hash remain the identities of the executed artifacts. None of these fields is described as an independent code audit or hardware attestation.

## Exact human-approved destination binding

Policy permission and human intent are separate authorities. `ActionProposal.host` is persisted as a canonical lowercase ASCII hostname and participates in the T3N policy decision. When the operator authorizes protected remediation, Spring signs that exact hostname as `approvedHost` in the one-time capability. The Spring→Gateway request carries the same `approved_host`, and the gateway includes it in body-equality verification together with the action, policy provenance, fields, logical private references and Protected Executor DID.

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
new evaluation + new human authorization required
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

This means `REDACT` is not merely a schema label in the UI: for the protected credential-revocation executor it produces a different serialized value-level egress payload. Private references remain separate; `verified_email` still becomes a T3N profile placeholder only inside the protected boundary and is never copied into the normal payload.

The UI uses four distinct terms to avoid overstating the claim: **Requested fields**, **Allowed for egress**, **Removed before egress** and **Protected egress payload**. Synthetic normal values may be shown because they are demonstration data; private/secret values must not be rendered.

Local regressions prove the closed server value source, cross-runtime hash vector, body-mismatch rejection, model/A2A rejection of privileged payload fields, Rust value-level intersection and textual accessibility of allowed/removed state. Optional live scenario `LIVE-NORMAL-PAYLOAD-MINIMIZATION` remains `NOT_RUN` until a controlled T3N testnet action/read-back endpoint executes it. It uses synthetic sentinels and accepts PASS only when read-back reports `must_egress_seen=true` and `must_not_egress_seen=false`; the sentinel strings themselves are not persisted in public evidence.

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
  -> Proposal Agent session authenticated
  -> Proposal Member grant ACTIVE
  -> Proposal checkDelegation(exact evaluate-action + minimum scopes) -> authorised=true
  -> effective Proposal access ACTIVE
  -> T3N policy ALLOW(A) + exact version/hash
  -> authenticated human authorizes exact action + destination A + policy provenance
  -> Protected Executor session authenticated
  -> Executor Member grant ACTIVE
  -> Executor checkDelegation(exact execute + verify + minimum scopes) -> authorised=true
  -> effective Executor access ACTIVE
  -> Spring signs one-time capability bound to destination A + Executor DID
  -> gateway validates body equality + expiry + anti-replay
  -> T3N resolves private action URL and requires actualHost == A
  -> T3N rechecks active version/hash + same host
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
| Credential compromised | `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none | Policy + human authorization + exact destination binding + protected execution + independent `REVOKED` read-back |
| Account takeover | `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none | Real AI proposal + real T3N policy evaluation |
| Record security incident | `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none | Real AI proposal + real T3N policy evaluation; expected no egress |
| Notify security contact | `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `verified_email` allowed | Real AI proposal + real T3N policy evaluation with logical private reference |

The cards are not permissions. Selecting a scenario changes only local synthetic demo context and the editable prompt; it does not call an API, authorize an action or predetermine the T3N decision. Switching scenario clears prior result state before the next analysis.

The current completion verifier understands the closed state `REVOKED`. For that reason, the interface exposes protected execution controls only for an actual `revoke-credential` proposal. It does not pretend that account isolation, incident recording or security notification already have a matching protected executor and completion verifier.

## Versioned T3N operational policy

Contract `0.4.0` separates configurable operational rules from immutable security invariants. The active canonical `PolicyDocument` is stored in the private T3N KV map `privacy-guard-policy`; React, Spring Boot and the model do not supply it to an evaluation request.

The configurable document may define enabled actions, purpose, allowed hosts, normal field allowlists, supported logical private references, host requirement and whether human authorization is required. Rust/WASM still owns the non-negotiable boundary: request/schema limits, fail-closed behavior, authenticated T3N identity/delegation constraints, forbidden secret classes, the closed private-reference vocabulary and safe host validation. A KV document cannot enable API keys, passwords, tokens or private keys as outbound fields.

Every valid policy evaluation returns:

```text
policy_version
policy_hash            canonical SHA-256
requires_human_authorization
```

Publication stores immutable `version:<version>` snapshots, a `current` pointer and publication/rollback history. Publishing different canonical content under an existing version is rejected. Rollback is explicit and may reference only an already persisted snapshot. Missing, corrupt, oversized or semantically invalid policy data fails closed.

Spring persists the version/hash with the policy decision. Human authorization requires versioned provenance and a valid persisted destination for executable egress actions. The one-time remediation capability signs the same version/hash plus the canonical approved hostname; the gateway verifies body equality; T3N first requires the private execution URL hostname to equal the approved hostname and then re-reads the current private policy before egress. If policy or destination changed after authorization, execution is rejected and the action must be evaluated and authorized again.

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
2. Read the product thesis and the Trust Flow before inspecting low-level metadata.
3. Confirm the top readiness badge reports the current T3N control-plane state.
4. Expand System readiness details and confirm Tenant, Proposal Agent and Protected Executor are authenticated as separate principals.
5. Distinguish Proposal/Executor Member grant from Effective T3N access; Proposal evaluation is ready only with Proposal effective ACTIVE, and protected remediation is operational only when Executor effective access is also ACTIVE.
6. In Protection flow, choose Credential compromised and inspect the synthetic attack prompt.
7. Click Analyze with agent and inspect the real model proposal.
8. Observe independent T3N TEE DENY, attacker.example and the exact policy version/hash; no protected execution is available.
9. Use Prepare safe path. This prepares/evaluates a minimum-scope revoke-credential proposal; it does not authorize or execute it.
10. Observe T3N ALLOW/REDACT and the minimum-data boundary. For REDACT, compare Requested fields, Allowed for egress, Removed before egress and the synthetic Protected egress payload.
11. Before authorization, confirm the panel shows the exact Approved destination hostname in addition to policy provenance.
12. Click Authorize credential revocation only after ALLOW or an executable REDACT minimum for that displayed destination; changing the protected destination requires a new evaluation and authorization.
13. When the environment supports synthetic egress/read-back, click Execute protected credential revocation and use Verify external state if verification remains pending.
14. Accept COMPLETED only when the Remediation execution and verification status shows Verification = VERIFIED and Final state = COMPLETED.
15. Inspect Local audit integrity separately from T3N provenance; use a local trail as proof only when its HMAC state is VERIFIED.
16. Open Evidence. Read Evidence summary first, then Observed outcomes, then expand Technical provenance.
17. Confirm 0 FAIL, T3N_TESTNET, full Source commit, Source tree CLEAN, separate Tenant/Proposal Agent/Protected Executor DIDs, Contract version/id, WASM SHA-256, policy provenance and honest NOT RUN boundaries.
18. If `LIVE-DESTINATION-BINDING` was executed, accept it only as PASS when A and B were both policy-allowed yet the contract reported BLOCKED_BEFORE_HTTP for B after A had been approved.
19. If `LIVE-NORMAL-PAYLOAD-MINIMIZATION` was executed, accept it only when controlled read-back reports must_egress_seen=true and must_not_egress_seen=false without exposing either sentinel value.
20. Optionally return to Protection flow and inspect Account takeover, Record security incident and Notify security contact; preset selection grants no authority and verified_email remains a logical reference rather than plaintext.
```

## Architecture and trust boundaries

```text
Untrusted prompt
      |
      v
AI provider (proposal only)
      |
      v
Browser / Spring Boot
      |
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
       bound to policy + destination + Executor DID
                    |
             atomic DB claim
                    |
             execute-remediation
             KV actualHost == approvedHost
             current policy re-check
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
- **Spring Boot owns durable business authorization and execution state.** It persists logical refs, trusted synthetic normal payload, policy provenance, the canonical approved destination, the human authorization transition and the remediation state machine.
- **Spring Boot also owns local business-audit integrity.** Sanitized audit events are chained with a backend-only HMAC key and authenticated head; broken/unverifiable integrity blocks protected local changes without rewriting history.
- **Gateway owns T3N sessions and privileged execution.** It requires service authentication and validates/consumes the one-time capability, including exact `approved_host` and `normalPayloadHash`, before execution.
- **Private KV owns remediation credentials/endpoints.** The protected credential, full action URL and verification URL are not browser inputs. The action URL hostname must still equal the operator-approved hostname at execution time.
- **T3N protected egress is the normal-payload minimization, profile-resolution and remediation boundary.** Responses are minimized before returning to application layers.
- **HTTP acceptance is not truth.** Completion is derived from an independent closed read-back, not from the original response code.

## Authority matrix

| Question | Source of authority |
|---|---|
| Which demo context is selected? | Browser presentation state only |
| What did the user ask? | Untrusted prompt |
| What action does the model suggest? | AI proposal |
| Which normal field names are requested? | AI proposal, still subject to T3N policy |
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
| High-confidence prompt literals are blocked before provider execution for the supported classes, with shared Java/TypeScript conformance fixtures | PROVED LOCAL | `prompt-privacy-guard.test.ts`, `agent-service.test.ts`, `IncidentDataMinimizerTest`, `privacy-conformance/sensitive-literal-corpus.json` |
| Prompt guard is partial/non-semantic and does not certify accepted text as PII-free | PROVED LOCAL | `PROMPT_PRIVACY_GUARD_SCOPE`, frontend copy/tests, Manual da Tela |
| Four enterprise presets map to existing policy actions without authorizing them | PROVED LOCAL | `scenarioDefinitions.ts` + `EnterpriseScenarioCatalog.test.tsx` |
| Scenario selection does not submit the prompt automatically | PROVED LOCAL | `EnterpriseScenarioCatalog.test.tsx` + controlled prompt flow |
| Tenant DID derives from authenticated T3N session | PROVED LOCAL | gateway session code/tests |
| Proposal Agent and Protected Executor use separate authenticated credentials/DIDs | PROVED LOCAL | session separation + status tests |
| Member-grant validity windows fail closed | PROVED LOCAL | `delegation-service.test.ts` |
| Effective access requires authenticated principal-side `checkDelegation()` only for an active Member grant | PROVED LOCAL | `delegation-service.test.ts` |
| Proposal and Executor checks use independent fixed least-privilege functions/scopes with no wildcard | PROVED LOCAL | `delegation-service.test.ts` |
| `pii_did` for the delegation check is the authenticated Tenant DID | PROVED LOCAL | `delegation-service.test.ts` |
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
| Remediation capability binds the exact canonical Approved destination | PROVED LOCAL | `RemediationAuthorizationSignerTest`, gateway verifier tests, `IncidentServiceTest` |
| Protected execution rejects private-KV host substitution before HTTP even when the alternate host is policy-allowed | PROVED LOCAL; LIVE OPTIONAL | Rust destination-binding tests; `LIVE-DESTINATION-BINDING` when executed on testnet |
| Protected execution rejects stale policy provenance | PROVED LOCAL | Rust/gateway remediation tests |
| Literal profile placeholders and unknown private refs are rejected | PROVED LOCAL | proposal schema + Spring validation + Rust policy tests |
| `verified_email` is the only current logical private reference | PROVED LOCAL | Rust policy/remediation mapping |
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
| New local audit events form a monotonic HMAC-SHA-256 chain with an authenticated tail head | PROVED LOCAL | `AuditIntegrityServiceTest` |
| Direct local audit content/link/sequence/T3N-provenance tampering and retained-tail deletion are detected | PROVED LOCAL | `AuditIntegrityServiceTest`, `AuditIntegrityGuardTest` |
| Concurrent local audit appends remain one linear sequence | PROVED LOCAL | `AuditIntegrityServiceTest` concurrency case |
| Audit key rotation is explicit and old retained events can be verified only with configured historical key material | PROVED LOCAL | `AuditIntegrityRotationTest` |
| Legacy rows are never silently promoted to cryptographically verified history | PROVED LOCAL | `AuditIntegrityServiceTest` |
| Local HMAC audit is immutable/tamper-proof or detects full DB+key/backend compromise | NOT CLAIMED | outside the DB-only threat model; no external monotonic audit anchor |
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

For a private value obtained through this supported logical-reference flow, the plaintext visibility contract is:

- AI/model: **NO**
- React/browser: **NO**
- Spring Boot/H2: **NO**
- gateway API/logical request: **NO**
- business audit/evidence: **NO**
- T3N protected egress: **YES**, transiently for placeholder resolution
- intended external service: **YES**, because it is the authorized recipient

This visibility contract does not make a blanket claim about arbitrary user-supplied prompt text. Users must not paste private values into prompts; the high-confidence pre-provider guard is partial and deliberately does not claim semantic/exhaustive PII coverage.

If the profile field is unavailable, user context is missing, placeholder is denied, delegation is not effectively authorized, the destination host differs from the Approved destination, the destination is not policy-authorized or policy provenance no longer matches, execution fails closed. Error text never returns the resolved value or private URL.

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
- `EXECUTION_DESTINATION_CHANGED` becomes a blocked `FAILED` execution with no protected HTTP call and requires a new evaluation + human authorization;
- normal payload key/value mutation after authorization fails capability equality before T3N execution;
- a forbidden secret key, unrequested trusted key, missing required executable field or minimized set that is not `ALLOW` fails before protected HTTP egress;
- an execution timeout after the request may have reached the provider becomes `UNVERIFIED`, not retryable `FAILED`;
- missing/mismatched operation id or request id becomes `UNVERIFIED`;
- missing/invalid/stale policy provenance blocks authorization/execution rather than silently falling back;
- verification outage or contradictory state becomes `UNVERIFIED`;
- `UNVERIFIED` with an operation id can invoke **Verify external state**, which performs read-back only;
- a reload fetches persisted remediation state through a read-only endpoint and does not execute/verify anything.

`requestId` is a stable logical idempotency key. The application prevents duplicate local initiation through its durable claim. It does **not** claim exactly-once or provider-level at-most-once unless the external provider explicitly honors the idempotency key.

## Terminal 3 integration findings

### Member Delegation and effective authorization

Member Delegation is treated as the Tenant-side grant document. A matching `ACTIVE` record is necessary but is not promoted directly to operational authority. Proposal and Executor checks are independent and use each authenticated grantee client. The check receives the resolved contract, authenticated Tenant DID and the fixed minimum requirement for that principal: Proposal checks only `evaluate-action`; Executor checks only `execute-remediation` and `verify-remediation`; both check scopes `incident_id`, `credential_id`, `reason`. Wildcards are rejected. `authorised=false` is `DENIED`; errors/malformed verdicts are `UNKNOWN`; known non-active Member states fail closed without invoking the effective check.

### Delegated `pii_did`

Every effective-delegation check and delegated execution derives `pii_did` internally from `tenantSession.getTenantDid()`. Browser, Java and LLM cannot supply or override the authorization subject.

### Profile placeholders

The application never lets the LLM/browser choose a raw placeholder. `verified_email` is mapped inside the TEE contract to the documented `profile.verified_contacts.email.value` marker, limiting the public application contract to an auditable domain vocabulary.

### Versioned private policy

Operational rules are provisioned to private T3N KV under immutable version snapshots and selected through the `current` pointer. The canonical policy SHA-256 is carried as provenance across evaluation, authorization, evidence and protected execution. Policy rollback is explicit; a hash is not described as attestation.

### Remediation destination and verification

The contract exposes separate `execute-remediation` and `verify-remediation` functions. Executor Member Delegation includes both only when required. The full action URL remains in private KV; the one-time human capability contains only the canonical Approved destination from the proposal. `execute-remediation` compares that value with the hostname extracted from the current private action URL before any HTTP call, then rechecks policy. The verification URL is independently configured/read from KV and may have another host because read-back is not the side effect that the operator authorized. Evidence orchestration derives the allowed HTTPS hosts from the configured action and verification endpoints and may add a synthetic B host only for the controlled testnet negative.

### Normal payload minimization

The model/A2A surface supplies field names only. Spring materializes bounded synthetic normal values from a closed table, persists them with the action and signs the deterministic `normalPayloadHash`. TypeScript verifies the same canonical hash before T3N execution. Rust then performs the actual value-level minimization by intersecting persisted values with the active policy's `allowed_fields`; it rejects forbidden secret keys and unrequested keys, requires the credential-revocation minimum and re-evaluates the minimized set before HTTP. The optional testnet evidence records only two controlled booleans proving that one sentinel arrived and one redacted sentinel did not.

## Tamper-evident local business audit

The local business audit is a separate application control from Terminal 3 network provenance. New sanitized events are authenticated with a versioned HMAC-SHA-256 chain scoped to the incident. The canonical event input binds the event and incident identifiers, monotonic local sequence, type, UTC timestamp, sanitized message, previous MAC and any persisted T3N sequence/hash/function. A separately authenticated chain-head record binds the final retained sequence/MAC, which makes tail deletion detectable in addition to row edits, inserted rows, sequence gaps and link changes.

Append is serialized through a pessimistic incident lock so concurrent writers cannot deliberately create the same local sequence or fork the chain. Verification runs from the oldest retained event to the head. The API returns integrity metadata separately from event content and separately from Activity Log reconciliation:

```text
Local integrity  VERIFIED / BROKEN / KEY_MISMATCH / LEGACY_UNVERIFIED
T3N provenance   MATCHED / UNMATCHED / LOCAL_ONLY / T3N_ONLY
```

`AUDIT_INTEGRITY_KEY` is backend-only and distinct from all T3N/provider/service/capability/operator credentials. `AUDIT_INTEGRITY_KEY_ID` and `AUDIT_INTEGRITY_PREVIOUS_KEYS` provide explicit versioned key rotation. Historical key material is required only while retained events signed by that key still need verification. Pre-HMAC events are `LEGACY_UNVERIFIED`; normal runtime keeps `AUDIT_INTEGRITY_ALLOW_LEGACY_BOOTSTRAP=false`, so old rows are not silently re-signed as if they were originally authenticated.

The claim boundary is intentionally narrow. This is **tamper-evident**, not immutable or tamper-proof storage. It targets DB/storage-only alteration when the attacker lacks the audit key. A runtime/backend compromise that can use the key, simultaneous DB+key compromise, or restoration of an older complete internally consistent database snapshot is outside the claim without a separate monotonic external audit anchor. HMAC verification is not hardware attestation and is not a T3N execution proof.

Broken/unverifiable local integrity blocks protected local changes rather than repairing or re-MACing history. Retention remains authoritative: when an incident expires, the application removes the audit events and its chain head instead of keeping `message` indefinitely to preserve verification.

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

The Protected Executor follows the same model independently using its own authenticated DID and its own fixed function set. The generated Agent Card is derived from the DID returned by the authenticated Proposal Agent session, not from a configured/hardcoded DID. It advertises only the supported `DID` service for that same identity, is bounded to the hosted-card size limit and rejects sensitive metadata/private-key-shaped values. The implementation does not advertise unsupported A2A/MCP services or x402 payment capability.

Operational commands:

```bash
cd t3n-gateway
npm run agent:card:verify    # read-only registry verification
npm run agent:card:publish   # explicit mutable host-card operation; may consume credits
```

The Evidence Center/status surface can show the observed onboarding state. The deployment manifest may contain the public card URI, SHA-256 of the exact resolved card, verification timestamp and service names. Those fields are public discoverability provenance; the hash is not a permission or attestation claim.

Local business audit and T3N Activity Log are independent evidence sources. `MATCHED` requires exact T3N sequence/hash/function plus the canonical actor for the function: Proposal Agent for `evaluate-action`, Protected Executor for `execute-remediation` and `verify-remediation`. `LOCAL_ONLY`, `T3N_ONLY` and `UNMATCHED` preserve the distinction when exact reconciliation is absent. An unavailable or truncated Activity Log is never converted into fabricated network proof, and it does not invalidate a separately `VERIFIED` local HMAC chain.

## Persistent trust-manifest rollback boundary

Before Tenant, Proposal Agent or Protected Executor identity is authenticated, the gateway verifies the official signed trust manifest and reads the persisted high-water mark for the selected network. If a floor exists, `fetchTrustedManifest(network, { minVersion })` is mandatory. All three sessions share the same `TrustManifestFloorStore`, so one runtime cannot accept separate rollback histories for the same network.

The floor is monotonic and network-scoped. It is written atomically to persistent `/data` storage and contains only the network, accepted version and acceptance timestamp. Missing state is valid only for first bootstrap; malformed, truncated or unreadable state fails closed and is never silently reset.

For judging and evidence, the claims are separate:

- **Trust anchor VERIFIED**: signed T3N manifest established the cluster trust boundary used for authentication.
- **Rollback floor PERSISTED**: a valid monotonic manifest-version floor was durably stored and reused across restarts.
- **Trust manifest version**: observed high-water version associated with the evidence bundle.
- **Policy version/hash**: exact canonical operational policy provenance; not a hardware-attestation statement.
- **Local audit VERIFIED**: the retained application HMAC chain and authenticated head verified with available key versions; not immutable storage or T3N attestation.
- **Hardware attestation**: not implied by any state above and not claimed without a separate execution-specific artifact.

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

The live orchestrator captures the source revision before it writes generated evidence files. A dirty working tree is rejected by default; the explicit non-submission override records `sourceTreeClean=false` rather than hiding the state. The manifest and testnet run must contain the same source SHA/tree state or the evidence API rejects the bundle. Before scenario execution, the orchestrator requires Proposal and Executor Member state plus effective state to both be `ACTIVE` for their fixed minimum checks. `PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means the scenario was not executed and is never counted as success. The profile-placeholder execution scenario remains `NOT_RUN` until a compatible profile/user context exists; local tests do not upgrade that claim to live proof.

With `EVIDENCE_RUN_DESTINATION_BINDING=true`, the testnet runner first proves A and B are independently policy-allowed, mutates the private action URL from A to B, requires the exact pre-HTTP destination mismatch and restores A in `finally`. Outside testnet this mutation is rejected. With `EVIDENCE_RUN_EGRESS_NEGATIVES=true`, the runner revokes Proposal and Executor independently, requires direct principal-side `checkDelegation()` to return `authorised=false`, exercises protected rejection where applicable, and restores the known-good minimum grants in `finally`. Raw grant documents and SDK authorization objects are not persisted in the bundle.

With `EVIDENCE_RUN_PAYLOAD_MINIMIZATION=true`, the testnet runner executes the controlled value-level minimization proof. PASS requires the read-back proof to report that the allowed synthetic sentinel was observed and the redacted synthetic sentinel was not observed. Evidence stores only those booleans; the sentinel strings remain prohibited from public bundle/log output. If the flag/environment is absent, the case remains `NOT_RUN`.

The live remediation scenario is stricter:

```text
attack DENY + policy provenance
   -> exact Approved destination still matches private action URL
   -> execute-remediation with same policy provenance
   -> PENDING_VERIFICATION
   -> operation_id present
   -> verify-remediation VERIFIED
   -> observed_state REVOKED
```

Anything less is not a successful completion proof.

### Evidence UI and capture contract

The `Evidence` area is intentionally ordered for judging: `Evidence summary` -> `Observed outcomes` -> `Technical provenance`. Summary surfaces PASS/FAIL/NOT RUN and the execution context before low-level hashes. Technical provenance keeps source/build, trust/network, identities/discoverability and contract/policy metadata available through disclosures without weakening any claim boundary.

The Playwright submission capture does not read evidence by visual position or `.evidence-metadata > div` order. It uses stable semantic hooks for fields that are part of the capture contract and still uses accessible roles/names for user actions. Before screenshots or `capture-metadata.json`, it requires the final UI states and records separate `tenantDid`, `proposalAgentDid` and `protectedExecutorDid`, plus full source commit, `CLEAN` source tree, contract id/version and WASM SHA-256. All three DIDs must be distinct and the leak detector remains mandatory.

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

When preparing egress evidence, configure `SECURITY_API_URL` and the separate `SECURITY_VERIFICATION_URL`. Both are sealed into the private map, and the delegation host allowlist is derived from those HTTPS endpoints. The optional destination-binding negative may add only the explicitly configured synthetic `EVIDENCE_DESTINATION_B_URL` host. Generated metadata is leak-scanned for operator credentials, T3N keys, AI provider key, service token, capability signing key, audit-integrity key, remediation key and configured sentinel.

## Screenshot shot list

1. Product header + judge-first Trust Flow + current T3N readiness badge.
2. Expanded **System readiness details** showing separate Tenant, Proposal Agent and Protected Executor identities.
3. Separate Proposal/Executor **Member grant** and **Effective T3N access** states; capture `Operational` only when protected remediation is ready, and show `Evaluation ready · execution blocked` when only Proposal is effectively authorized.
4. **Protection flow** with Credential compromised selected and the statement that presets are not permissions.
5. Attack prompt + provider/model provenance + model proposal after **Analyze with agent** + `DENY` + policy version/hash.
6. `REDACT` data-minimization evidence showing Requested fields, Allowed for egress, Removed before egress and the synthetic Protected egress payload so value-level removal is visible.
7. Notify security contact selected, showing logical `verified_email` and no plaintext address/raw placeholder.
8. **Prepare safe path** result showing legitimate minimum credential-revocation proposal + `ALLOW` + policy provenance.
9. **Approved destination** visible in the protected-remediation panel before human authorization, without revealing the private full URL.
10. **Authorize credential revocation** shown separately from **Execute protected credential revocation**, bound to the same version/hash, exact destination and Protected Executor.
11. Execution/verification panel showing Authorization, Execution, Verification and Final state; use **Verify external state** for read-back-only retry when available.
12. If captured, `Destination changed` must show re-evaluate/re-authorize guidance rather than a generic outage.
13. Local audit integrity shown separately from T3N Activity Log provenance; capture `VERIFIED` only when HMAC verification actually succeeded.
14. Verified remediation screenshot only after `Verification = VERIFIED` and `Final state = COMPLETED`.
15. **Evidence** with `Evidence summary`, `Observed outcomes`, then expanded `Technical provenance`; include full Source commit, Source tree state, separate Proposal Agent/Protected Executor DIDs, T3N_TESTNET, contract/WASM/policy provenance and optional scenarios honestly PASS/FAIL/NOT RUN.

Never capture passwords, cookies, T3N keys, provider key, service/capability keys, audit-integrity key, remediation secret, resolved profile PII, `.env` or raw logs.

## Demo video storyboard

```text
0–10s    Product thesis + Trust Flow: AI proposes; it does not own authority
10–25s   Expand System readiness details; show three authenticated T3N identities
25–40s   Show Agent Card vs Member grant vs Effective T3N access
40–65s   Protection flow -> Credential compromised -> Analyze with agent -> malicious structured proposal
65–85s   Independent T3N TEE DENY + policy provenance; no protected egress
85–105s  Switch scenarios; show isolation, record incident and logical verified_email context
105–125s Prepare safe path -> minimum credential revocation -> ALLOW/REDACT + value-level normal-payload minimization + policy version/hash
125–140s Show exact Approved destination, then authorize credential revocation
140–155s Show capability/destination/normalPayloadHash binding + Local audit integrity separately from T3N Activity provenance
155–170s Execute protected credential revocation -> private-host equality -> active policy recheck -> minimized payload -> PENDING_VERIFICATION
170–175s Verify external state -> VERIFIED/COMPLETED when available
175–180s Evidence summary -> outcomes -> technical provenance + exact NOT_RUN boundaries
```

## UX and claim wording rules

The submission must lead with user/business meaning, then expose the technical proof. Technical labels remain precise.

- **enterprise scenario**: synthetic demonstration context and prompt preset, never a permission or policy decision;
- **agent proposal**: model-produced structured request, not authorization;
- **Requested fields**: field names selected by the untrusted proposal; not values and not authority by themselves;
- **Allowed for egress**: normal field keys allowed by the active T3N policy for the execution being constructed;
- **Removed before egress**: requested keys excluded by minimization and not serialized into the protected HTTP body;
- **Protected egress payload**: bounded trusted synthetic normal values after T3N minimization, never a model-supplied payload;
- **pre-provider privacy guard**: high-confidence, partial control for explicitly supported structured literals; not a semantic/exhaustive PII scanner, and an accepted prompt is not certified PII-free or safe;
- **authenticated**: a T3N session proved a principal identity and yielded its canonical DID;
- **registered**: the public Proposal Agent Card resolved and matched the authenticated DID; not authorization;
- **Member grant**: Tenant-side grant record with grantee, contract, functions, scopes, hosts and validity window; necessary but not sufficient;
- **effective access**: runtime result of the principal-specific minimum authorization requirement; `ACTIVE` only when Member grant is active and T3N returns `authorised=true`, `DENIED` on explicit denial/known non-active grant, `UNKNOWN` on inconclusive validation;
- **Policy-allowed destination**: a hostname belonging to the set permitted by the active policy; not human intent by itself;
- **Approved destination**: exact canonical hostname shown to the operator and bound to the human authorization/capability;
- **Destination changed**: private action configuration now resolves to another hostname; execution is blocked and a new evaluation/authorization is required;
- **human authorized**: business authorization persisted for the exact action, Approved destination, policy provenance, trusted normal-payload hash and Protected Executor DID;
- **local audit integrity VERIFIED**: retained HMAC chain, sequence/linkage and authenticated head validated with configured key versions; not immutable storage, T3N provenance or hardware attestation;
- **local audit integrity BROKEN**: retained history diverged from the authenticated chain/head; protected changes are blocked and history is not auto-repaired;
- **LEGACY_UNVERIFIED**: retained pre-HMAC events remain visible but are not presented as cryptographically authenticated history;
- **source commit**: full public Git revision captured before evidence generation; source traceability, not independent verification;
- **source tree CLEAN**: no tracked or untracked working-tree changes at capture time; reproducibility signal, not security certification;
- **source tree DIRTY**: source differed from the recorded commit; disclosed explicitly and rejected for submission evidence by default;
- **policy version**: immutable operational ruleset identifier loaded from private T3N KV;
- **policy hash**: deterministic canonical SHA-256 proving policy provenance, not hardware attestation;
- **logical private reference**: category such as `verified_email`, not the private value;
- **resolved by T3N at egress**: only claim for executions where T3N actually resolved the placeholder;
- **accepted / pending verification**: execution endpoint acknowledged the operation; final state is not yet proven;
- **verified**: independent read-back matched the closed expected state;
- **completed**: Spring persisted completion only after verified read-back;
- **unverified**: outcome is ambiguous/not confirmed and no automatic re-execution occurs;
- **execution proof**: short-lived server-to-gateway capability bound to the exact approved request including destination and trusted normal-payload hash; not hardware attestation;
- **proved live**: matching live evidence/capture exists.

Do not say “Verified source” solely because a Git SHA/tree state is present, “Member grant ACTIVE = authorized”, “registered = authorized”, “Agent Card = attestation”, “policy allows B so the human approved B”, “REDACT proves value-level minimization” unless the protected executor actually constructs the outbound subset, “local audit is immutable/tamper-proof”, “local audit VERIFIED = T3N MATCHED”, “guarantees GDPR compliance”, “hardware verified”, “exactly once”, “at most once”, “profile resolution proved live”, “all four scenarios execute end-to-end”, “prompt is PII-free because it passed the guard” or “completed from HTTP 2xx” without corresponding evidence/contract.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new Tenant, Proposal Agent and Protected Executor credentials, operator credentials, provider key, service/capability keys, audit-integrity key and persistent gateway `/data`. Existing private keys are not transferred through GitHub/UI. Profile-backed live evidence must use a dedicated test profile with synthetic data.

This file is the repository source of truth for the public submission narrative and handover model.
