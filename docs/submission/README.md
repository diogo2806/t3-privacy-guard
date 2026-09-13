# T3 Privacy Guard — Submission & Judge Guide

## Product position

**T3 Privacy Guard is an enterprise trust runtime for AI agents.** Its purpose is not to make the model itself trustworthy. Its purpose is to keep policy, identity, private-data resolution, business authorization and completion proof outside the model even when the model is manipulated.

The product thesis is intentionally simple:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

The current challenge implementation applies that pattern to confidential incident response. The Rust policy recognizes four concrete operational actions: credential revocation, account isolation, incident recording and security notification. The Protection demo exposes all four as business-readable presets while preserving the strongest end-to-end execution/read-back path for credential revocation only.

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host`, normal field names and enumerated logical private-data references. It cannot provide a policy decision, DID, override, secret, execution capability or literal T3N profile placeholder.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM policy through a dedicated authenticated **Proposal Agent DID** and Tenant `pii_did`. A malicious exfiltration proposal receives `DENY`. A minimum legitimate proposal can receive `ALLOW`, but `ALLOW` is still not execution: an authenticated operator must explicitly authorize remediation, after which Spring emits a short-lived one-time signed capability bound to the exact action, decision, normal fields, logical private references, policy provenance and the authenticated **Protected Executor DID**. The gateway verifies service authentication, capability integrity, expiry, body equality and anti-replay state before protected T3N execution.

Proposal and execution authority are intentionally separate. The Proposal Agent has a minimum Member grant for `evaluate-action`; the Protected Executor has a different credential/DID and a separate minimum Member grant for `execute-remediation` and `verify-remediation`. An `ACTIVE` Member grant is configuration/read-back evidence, not the final authorization claim. Runtime readiness additionally requires `T3nClient.checkDelegation()` to be executed by the authenticated principal itself with the canonical Tenant DID, exact contract, exact functions and exact scopes. Only `authorised=true` becomes effective `ACTIVE`; `authorised=false`, errors and inconclusive responses fail closed.

For private profile data, the application carries only a category such as `verified_email`. The Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`; the real value can be resolved only by T3N during protected egress and is not returned to React, Java, the model or gateway responses.

Protected credential revocation is fail-safe under retries. Spring creates a persistent atomic claim before egress. The TEE sends `requestId` as the stable idempotency key, but a 2xx only produces `PENDING_VERIFICATION`. A distinct T3N `verify-remediation` read-back must observe the matching `operation_id` and the closed expected state `REVOKED` before the business state becomes `COMPLETED`. Ambiguous outcomes become `UNVERIFIED`; they may be re-verified but are never automatically executed again.

The operational policy used by contract `0.4.0` is versioned in private T3N KV. Each decision carries the exact `policyVersion` and deterministic SHA-256 `policyHash`; critical invariants remain compiled in WASM. Missing or invalid policy fails closed. Human authorization and protected execution are bound to the same version/hash so a policy change after approval cannot silently reuse stale authority.

The project reports only verifiable state: `NOT_RUN` never becomes `PASS`, simulated output is not labelled live, an `ACTIVE` Member grant is not labelled effective authorization, profile-placeholder resolution is not labelled proved live until a compatible testnet profile actually executes it, external execution is not labelled completed from HTTP acceptance alone, and hardware attestation is not claimed without a concrete artifact.

## Why this is more than PII detection

A normal PII filter answers questions such as “does this prompt contain an email address?”. T3 Privacy Guard addresses a larger authority problem:

```text
What may the agent propose?
        |
Who is the authenticated Proposal Agent?
        |
Which Member grant is configured for that principal?
        |
Does T3N currently authorize that exact principal/function/scope?
        |
Which policy version governs this decision?
        |
Which action/purpose/host/data are allowed?
        |
Has a human authorized the exact action and policy provenance?
        |
Which separate Protected Executor may perform the action?
        |
Does T3N currently authorize that Executor's exact protected functions/scopes?
        |
Can this exact authorization be replayed?
        |
Did the external side effect really reach the expected state?
```

A model can therefore remain useful while being structurally unable to grant itself the missing authority.

## 60-second judge story

### Attack path

```text
Prompt injection
  -> real model proposes api_key + attacker.example
  -> proposal is persisted as untrusted output
  -> authenticated Proposal Agent DID is added outside the model
  -> T3N effective delegation check is independent from grant read-back
  -> T3N Rust/WASM loads the active versioned policy
  -> policy evaluates the request
  -> DENY + policy provenance
  -> no human authorization
  -> no Protected Executor invocation
  -> no protected egress
```

The important observation is not merely that a keyword was detected. The model is allowed to produce the malicious proposal, but **the model does not control the decision or authorization boundary**.

### Legitimate path

```text
Minimum legitimate credential-revocation proposal
  -> Proposal effective T3N access CONFIRMED
  -> T3N policy ALLOW + exact version/hash
  -> authenticated human authorizes exact action + policy provenance + Executor DID
  -> Spring signs one-time capability
  -> gateway validates body equality + expiry + anti-replay
  -> Executor effective T3N access CONFIRMED
  -> T3N rechecks active version/hash
  -> protected execution
  -> external acknowledgement = PENDING_VERIFICATION
  -> separate read-back
  -> VERIFIED REVOKED
  -> Spring records COMPLETED
```

The important observation is that no single success signal is trusted to mean more than it proves.

## Current enterprise actions and scenario catalog

The current Rust policy defines these real action contracts, and the dashboard exposes each one as a synthetic demonstration preset:

| Business scenario | Action | Purpose | Allowed normal fields | Private reference | Current demo depth |
|---|---|---|---|---|---|
| Credential compromised | `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none | Policy + human authorization + protected execution + independent `REVOKED` read-back |
| Account takeover | `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none | Real AI proposal + real T3N policy evaluation |
| Record security incident | `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none | Real AI proposal + real T3N policy evaluation; expected no egress |
| Notify security contact | `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `verified_email` allowed | Real AI proposal + real T3N policy evaluation with logical private reference |

The cards are not permissions. Selecting a scenario changes only local synthetic demo context and the editable prompt; it does not call an API, authorize an action or predetermine the T3N decision. The actual model proposal remains visible and is what the policy evaluates.

The current completion verifier understands the closed state `REVOKED`. For that reason, the interface exposes protected execution controls only for an actual `revoke-credential` proposal. It does not pretend that account isolation, incident recording or security notification already have a matching protected executor and completion verifier.

Switching scenario clears the prior scenario result in the browser before the next analysis, preventing evidence from one preset from being visually attributed to another.

## Versioned T3N operational policy

Contract `0.4.0` separates configurable operational rules from immutable security invariants. The active canonical `PolicyDocument` is stored in the private T3N KV map `privacy-guard-policy`; React, Spring Boot and the model do not supply it to an evaluation request.

The configurable document may define enabled actions, purpose, allowed hosts, normal field allowlists, supported logical private references, host requirement and whether human authorization is required. Rust/WASM still owns the non-negotiable boundary: request/schema limits, fail-closed behavior, authenticated T3N identity/delegation constraints, forbidden secret classes, the closed private-reference vocabulary and safe host validation. A KV document cannot enable API keys, passwords, tokens or private keys as outbound fields.

Every valid policy evaluation returns the decision together with:

```text
policy_version
policy_hash            canonical SHA-256
requires_human_authorization
```

Publication is explicit. The gateway setup script stores immutable `version:<version>` snapshots, a `current` pointer and publication/rollback history. Publishing different canonical content under an existing version is rejected. Rollback requires `T3N_POLICY_ROLLBACK_VERSION` and may reference only an already persisted snapshot. Missing, corrupt, oversized or semantically invalid policy data fails closed.

Spring persists the version/hash with the policy decision. Human authorization requires versioned provenance. The one-time remediation capability signs the same version/hash, the gateway verifies body equality, and T3N protected execution re-reads the current private policy before egress. If the policy changed after authorization, execution is rejected and the action must be evaluated again.

The policy hash proves which canonical rules produced a decision; it is **not** hardware attestation.

## Judge quick path

```text
1. Sign in as application operator
2. Read the product thesis before inspecting low-level metadata
3. Confirm Tenant / Proposal Agent / Protected Executor authentication separately
4. Confirm Proposal Member grant and Proposal effective T3N access are distinct states
5. Confirm Executor Member grant and Executor effective T3N access are distinct states
6. Confirm Contract is resolved; do not infer readiness from grant read-back alone
7. Choose Credential compromised and inspect the synthetic attack prompt
8. Click Ask agent
9. Inspect the real model's structured Agent proposal
10. Observe independent T3N TEE DENY and the exact policy version/hash
11. Switch through Account takeover, Record security incident and Notify security contact
12. Confirm each selection only prepares editable synthetic input and prior results are cleared
13. Use Ask agent and inspect the real proposal + real T3N DENY/REDACT/ALLOW result
14. For Notify security contact, confirm only logical verified_email appears, never plaintext email or raw profile placeholder
15. Return to Credential compromised and prepare the minimum revocation path
16. Observe T3N ALLOW/REDACT and the minimum-data boundary
17. Record explicit human authorization only after ALLOW under the displayed policy version/hash
18. Execute protected credential revocation only while Executor effective access is Confirmed
19. Confirm execution is bound to the same policy provenance and Executor DID
20. Observe PENDING_VERIFICATION or the verification transition
21. Accept COMPLETED only when independent read-back shows VERIFIED
22. Open Evidence and confirm exact T3N_TESTNET claims, contract/WASM/policy provenance, both effective delegation checks and NOT_RUN boundaries
```

## Architecture and trust boundaries

```text
Untrusted prompt
      |
      v
AI provider (proposal only)
      | logical private ref, never value
      v
Browser / Spring Boot
      |
      | service-authenticated internal call
      v
T3N Gateway
      |
      +--> authenticated Tenant session -> canonical pii_did
      |
      +--> authenticated Proposal Agent session
      |       |
      |       +--> Member grant read-back
      |       +--> checkDelegation(evaluate-action + exact scopes)
      |       +--> T3N / Rust WASM policy
      |                 |
      |              DENY / REDACT / ALLOW
      |                         |
      |                 authenticated human
      |                         |
      |                  one-time capability
      |               bound to policy + Executor DID
      |                         |
      +--> authenticated Protected Executor session
              |
              +--> separate Member grant read-back
              +--> checkDelegation(execute + verify + exact scopes)
              +--> protected execution
                         |
                  PENDING_VERIFICATION
                         |
                  verify-remediation
                         |
              VERIFIED -> COMPLETED
              otherwise -> UNVERIFIED
```

Trust model:

- **Prompt is untrusted.** It may contain instruction injection and never becomes an authorization source.
- **Scenario selection is presentation state.** It loads synthetic input and grants no authority.
- **The model is not a security boundary.** It can only call one proposal tool with a closed JSON schema.
- **Unknown or privileged model fields are rejected.** Decisions, overrides, identities, credentials, secrets, API keys and literal `{{profile...}}` markers are rejected before T3N evaluation.
- **Private data is referenced, not copied.** The model/application may request `verified_email`; only Rust/WASM can convert it to the official T3N profile marker.
- **T3N identities are server-derived.** Tenant, Proposal Agent and Protected Executor DIDs come from their authenticated sessions, never from model input or hardcoded configuration.
- **Member grant and effective authorization are different.** `getMemberDelegation()` proves what grant was configured/read; `checkDelegation()` through the authenticated principal proves whether T3N authorizes the exact contract/functions/scopes at that moment.
- **Proposal and Executor authorization are independent.** Proposal is checked only for `evaluate-action`; Executor is checked only for `execute-remediation` and `verify-remediation`. Neither check can authorize the other principal.
- **Rust/WASM owns immutable security invariants.** The model and KV policy cannot manufacture authority or relax forbidden-secret/identity/delegation boundaries.
- **Private T3N KV owns versioned operational rules.** Each accepted decision exposes deterministic version/hash provenance.
- **Spring Boot owns durable business authorization and execution state.** It persists logical refs, policy provenance, the human authorization transition and the remediation state machine.
- **Gateway owns T3N sessions and privileged execution.** It requires service authentication and validates/consumes the one-time capability before execution.
- **Private KV owns remediation credentials/endpoints.** The protected credential, action URL and verification URL are not browser inputs.
- **T3N protected egress is the profile-resolution and remediation boundary.** Responses are minimized before returning to application layers.
- **HTTP acceptance is not truth.** Completion is derived from an independent closed read-back, not from the original response code.

## Authority matrix

| Question | Source of authority |
|---|---|
| Which demo context is selected? | Browser presentation state only |
| What did the user ask? | Untrusted prompt |
| What action does the model suggest? | AI proposal |
| Which Proposal Agent identity is evaluating? | Authenticated Proposal Agent T3N session |
| Which Protected Executor identity may execute/verify? | Authenticated Executor T3N session |
| Which tenant/data owner is the authorization subject? | Authenticated Tenant session |
| Which grant is configured for a principal? | Tenant Member Delegation read-back |
| Is that principal effectively authorized for the exact call now? | `T3nClient.checkDelegation()` invoked by that authenticated principal with canonical Tenant DID + exact contract/functions/scopes |
| Which operational rules are active? | Versioned private T3N KV policy |
| Which critical rules cannot be relaxed? | Rust/WASM invariants |
| Is action/purpose/host/data allowed? | Rust/WASM evaluation of active policy |
| Is business remediation approved? | Authenticated human operator bound to policy provenance + Executor DID |
| Is this exact execution approved by the application now? | Signed one-time capability |
| May a private value be resolved? | Closed Rust mapping + T3N protected boundary |
| Did the side effect complete? | Independent read-back + Spring state machine |

## Security claims matrix

| Claim | Current status | Source of truth |
|---|---|---|
| Real configured model produces structured proposals | PROVED LOCAL | provider adapter + agent/backend tests |
| Tool schema cannot accept decision/override/DID/secret authority fields | PROVED LOCAL | `proposal-schema.test.ts` |
| Four enterprise presets map to the four existing policy actions without authorizing them | PROVED LOCAL | `scenarioDefinitions.ts` + `EnterpriseScenarioCatalog.test.tsx` |
| Scenario selection does not submit the prompt automatically | PROVED LOCAL | `EnterpriseScenarioCatalog.test.tsx` + controlled prompt flow |
| Canonical policy hashing is deterministic | PROVED LOCAL | `policy-document.test.ts` |
| Different canonical policy content changes the SHA-256 | PROVED LOCAL | `policy-document.test.ts` |
| Reusing a version with different content is rejected | PROVED LOCAL | policy provisioner + tests |
| Missing/invalid policy fails closed | PROVED LOCAL | Rust policy tests + gateway contract path |
| Critical forbidden-secret/private-ref invariants cannot be relaxed by KV policy | PROVED LOCAL | Rust adversarial/policy tests |
| Policy version/hash propagate through decision, persistence, UI and evidence metadata | PROVED LOCAL | backend/frontend/evidence tests |
| Remediation capability binds exact policy version/hash and Executor DID | PROVED LOCAL | signer/verifier + remediation tests |
| Protected execution rejects stale policy provenance | PROVED LOCAL | Rust/gateway remediation tests |
| Literal profile placeholders and unknown private refs are rejected | PROVED LOCAL | proposal schema + Spring validation + Rust policy tests |
| `verified_email` is the only current logical private reference | PROVED LOCAL | Rust policy/remediation mapping |
| `verified_email` is allowed only for `notify-security` / `incident-notification` | PROVED LOCAL | Rust policy tests |
| Rust maps `verified_email` to `{{profile.verified_contacts.email.value}}` | PROVED LOCAL | Rust remediation regression test |
| Java/H2 persists logical refs, not plaintext profile values | PROVED LOCAL | entity/service/API model + tests |
| Human capability binds private refs as well as normal fields | PROVED LOCAL | signer/verifier tests |
| Reflected upstream private value is absent from contract result schema | PROVED LOCAL | Rust remediation regression test |
| Tenant DID derives from authenticated T3N session | PROVED LOCAL | gateway session code/tests |
| Proposal Agent and Protected Executor use separate credentials/DIDs | PROVED LOCAL | session separation + contract tests |
| Delegated calls bind `pii_did` to canonical Tenant DID | PROVED LOCAL | gateway contract/delegation tests |
| `ACTIVE` Member grant alone cannot produce ready state | PROVED LOCAL | delegation service + backend/frontend readiness tests |
| Proposal `checkDelegation` runs through Proposal client for exact `evaluate-action` functions/scopes | PROVED LOCAL | `delegation-service.test.ts` |
| Executor `checkDelegation` is independent and checks exact protected functions/scopes | PROVED LOCAL | `delegation-service.test.ts` |
| `authorised=false`, errors and inconclusive delegation responses fail closed | PROVED LOCAL | gateway/backend/frontend tests |
| Complete Member Delegation documents are not exposed in status/evidence UI | PROVED LOCAL | sanitized delegation status contract |
| Protected remediation requires service auth + signed human capability | PROVED LOCAL | gateway authorization boundary/tests |
| Concurrent requests acquire at most one local execution claim | PROVED LOCAL | pessimistic claim + concurrency tests |
| HTTP 2xx cannot directly produce `COMPLETED` | PROVED LOCAL | Rust contract + Java state-machine tests |
| `COMPLETED` requires independent read-back of matching operation/state | PROVED LOCAL | Rust/Java verification tests |
| Timeout/ambiguous ACK does not automatically re-execute | PROVED LOCAL | `IncidentServiceTest` |
| Reload reads persisted execution state without egress/reverification | PROVED LOCAL | `RemediationQueryServiceTest` + frontend API flow |
| Real model attack -> T3N DENY on live testnet | NOT CLAIMED | only after matching public capture/evidence run |
| Effective Proposal + Executor T3N authorization on live testnet | NOT CLAIMED until fresh bundle | `evidence:live` records sanitized Member/effective states and exact checked functions/scopes |
| T3N profile placeholder resolves verified email on live testnet | NOT RUN | requires compatible profile/user context and matching evidence |
| Verified external remediation on live testnet | NOT CLAIMED | only after execute + independent verify scenario passes |
| Revoked delegation blocks protected egress on live testnet | NOT CLAIMED | only after matching live evidence |
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

`private_refs` contains domain-level categories only. The model cannot submit `{{profile...}}`, `profile.*`, a private value, a new private namespace or policy configuration. Provider failure, invalid JSON, missing/multiple tool calls, extra keys or unsafe authority fields fail closed.

## Structural private-data flow

```text
Agent request: verified_email
        |
        v
Spring/H2 stores: verified_email
        |
        v
T3N policy checks action + purpose + host + private ref
        |
        v
Human authorization capability signs privateRefsHash + policy provenance
        |
        v
Gateway verifies exact private_refs + policy version/hash
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

Plaintext visibility contract:

- AI/model: **NO**
- React/browser: **NO**
- Spring Boot/H2: **NO**
- gateway API/logical request: **NO**
- business audit/evidence: **NO**
- T3N protected egress: **YES**, transiently for placeholder resolution
- intended external service: **YES**, because it is the authorized recipient

If the profile field is unavailable, user context is missing, placeholder is denied, effective delegation is denied/unknown, the destination host is not authorized or policy provenance no longer matches, execution fails closed. Error text never returns the resolved value.

## Verified remediation flow

The current verified completion flow is specifically the credential-revocation path:

```text
Proposal checkDelegation = authorised=true
      |
T3N TEE ALLOW for revoke-credential
      | exact policy version/hash
Authenticated operator authorizes
      | same policy provenance + Executor DID
Spring checks persisted action + ALLOW
      |
HMAC capability binds fields + private refs + policy provenance + Executor
      |
Atomic pessimistic claim creates EXECUTING
      |
Gateway verifies service token + capability
      |
Executor checkDelegation = authorised=true
      |
T3N execute-remediation rechecks active policy version/hash
      | requestId -> Idempotency-Key
      v
PENDING_VERIFICATION + operation_id
      |
T3N verify-remediation
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
- an execution timeout after the request may have reached the provider becomes `UNVERIFIED`, not retryable `FAILED`;
- missing/mismatched operation id or request id becomes `UNVERIFIED`;
- missing/invalid/stale policy provenance blocks authorization/execution rather than silently falling back;
- missing/denied/unknown effective delegation blocks the corresponding evaluation/execution readiness;
- verification outage or contradictory state becomes `UNVERIFIED`;
- `UNVERIFIED` with an operation id can invoke **Verify external state**, which performs read-back only;
- a reload fetches persisted remediation state through a read-only endpoint and does not execute/verify anything.

`requestId` is a stable logical idempotency key. The application prevents duplicate local initiation through its durable claim. It does **not** claim exactly-once or provider-level at-most-once unless the external provider explicitly honors the idempotency key.

## Terminal 3 integration findings

### Member Delegation, `scopes` and effective authorization

The project validates/sends non-empty scopes even where simplified examples omit them, following the field reference. Member grant read-back and effective authorization are deliberately separate: `getMemberDelegation()` is used to observe the configured grant/window/functions/scopes, while the authenticated delegated principal calls `T3nClient.checkDelegation({ contract, pii_did, functions, scopes })` using the canonical Tenant DID and exact least-privilege functions/scopes. `authorised=true` is required for effective `ACTIVE`; `false`, exceptions or inconclusive payloads fail closed.

### Delegated `pii_did`

Every delegated check/execution derives `pii_did` internally from `tenantSession.getTenantDid()`. Browser, Java and LLM cannot supply or override the authorization subject.

### Profile placeholders

The application never lets the LLM/browser choose a raw placeholder. `verified_email` is mapped inside the TEE contract to the documented `profile.verified_contacts.email.value` marker, limiting the public application contract to an auditable domain vocabulary.

### Versioned private policy

Operational rules are provisioned to private T3N KV under immutable version snapshots and selected through the `current` pointer. The canonical policy SHA-256 is carried as provenance across evaluation, authorization, evidence and protected execution. Policy rollback is explicit; a hash is not described as attestation.

### Remediation verification

The contract exposes separate `execute-remediation` and `verify-remediation` functions. The Protected Executor Member grant and effective check include both only when required. Evidence orchestration derives the allowed HTTPS hosts from the configured remediation and verification endpoints rather than broadening the grant arbitrarily.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new Tenant/Proposal/Executor credentials, operator credentials, provider key, service/capability keys and persistent gateway `/data`. Existing private keys are not transferred through GitHub/UI. Profile-backed live evidence must use a dedicated test profile with synthetic data.

## Evidence model

```text
WASM bytes -> SHA-256 -> deployment-manifest.json
policy doc -> SHA-256 ---------|
                               +-> same Tenant / Proposal / Executor DIDs
                                            + contract / version / WASM / policy
                                            |
Proposal + Executor checkDelegation --------+
  exact functions/scopes + effective state  |
                                            v
                                     testnet-run.json
```

`PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means the scenario was not executed and is never counted as success. The profile-placeholder execution scenario remains `NOT_RUN` until a compatible profile/user context exists; local tests do not upgrade that claim to live proof.

The live remediation scenario is stricter:

```text
Proposal effective access CONFIRMED
   -> attack DENY + policy provenance
   -> Executor effective access CONFIRMED
   -> execute-remediation with same policy provenance
   -> PENDING_VERIFICATION
   -> operation_id present
   -> verify-remediation VERIFIED
   -> observed_state REVOKED
```

Anything less is not a successful completion proof.

### Local controls

```bash
bash scripts/run-local-evidence.sh
```

### Live T3N evidence

```bash
cd t3n-gateway
npm install
npm run evidence:live
```

When preparing egress evidence, configure `SECURITY_API_URL` and the separate `SECURITY_VERIFICATION_URL`. Both are sealed into the private map, and the Executor grant host allowlist is derived from those HTTPS endpoints. Generated metadata is leak-scanned for operator credentials, Tenant/Proposal/Executor T3N keys, AI provider key, service token, capability signing key, remediation key and configured sentinel. Evidence metadata also carries the exact policy version/hash used by the run. The testnet bundle adds only sanitized delegation states and checked function/scope lists; it never embeds complete grant documents or secrets.

## Screenshot shot list

Screenshots must tell the same authority-separation story as the product, not merely prove that screens exist.

1. Product header + live T3N operational status showing Proposal and Executor separately.
2. Expanded technical status showing `Member grant` and `Effective T3N access` as different rows for both principals; Confirmed only for a real effective check.
3. Four enterprise scenario cards with Credential compromised selected and the statement that presets are not permissions.
4. Attack prompt + provider/model provenance + model proposal + `DENY` + policy version/hash.
5. `REDACT` data-minimization evidence.
6. Notify security contact selected, showing logical `verified_email` and no plaintext address/raw placeholder.
7. Private-reference panel showing `Verified email`, Agent plaintext `NO`, Java plaintext `NO`, T3N egress resolution boundary.
8. Legitimate credential-revocation proposal/minimum remediation + `ALLOW` + policy provenance.
9. Human authorization separate from execution and bound to the same version/hash and Executor DID.
10. Execution/verification panel showing the state machine.
11. Verified remediation screenshot only after `Verification = VERIFIED` and `Final state = COMPLETED`.
12. Evidence Center with T3N_TESTNET metadata/results, contract/WASM/policy provenance and optional scenarios honestly PASS/FAIL/NOT RUN.

Never capture passwords, cookies, T3N keys, provider key, service/capability keys, remediation secret, resolved profile PII, `.env` or raw logs.

## Demo video storyboard

```text
0–10s    Product thesis: AI proposes; it does not own authority
10–25s   Show Proposal vs Protected Executor identities and Member grant vs effective access
25–40s   Show four enterprise presets and explain that selection grants no authority
40–65s   Credential attack prompt -> real provider -> malicious structured proposal
65–85s   Independent T3N TEE DENY + policy provenance; no protected egress
85–105s  Switch scenarios; show isolation, record incident and logical verified_email notification context
105–125s Minimum credential-revocation request -> ALLOW/REDACT + policy version/hash
125–140s Explicit human authorization bound to policy provenance + Executor DID
140–160s Protected Executor -> effective check -> active policy recheck -> accepted/PENDING_VERIFICATION
160–175s Independent read-back -> VERIFIED/COMPLETED when available
175–180s Evidence Center -> exact proof status and NOT_RUN boundaries
```

## UX and claim wording rules

The submission must lead with user/business meaning, then expose the technical proof. Technical labels remain precise.

- **enterprise scenario**: synthetic demonstration context and prompt preset, never a permission or policy decision;
- **agent proposal**: model-produced structured request, not authorization;
- **policy version**: immutable operational ruleset identifier loaded from private T3N KV;
- **policy hash**: deterministic canonical SHA-256 proving policy provenance, not hardware attestation;
- **logical private reference**: category such as `verified_email`, not the private value;
- **resolved by T3N at egress**: only claim for executions where T3N actually resolved the placeholder;
- **authenticated**: a principal session proved control of its credential and returned its canonical DID;
- **registered**: the Proposal Agent public Agent Card resolved and passed closed validation;
- **Member grant Active**: the configured grant was observed/read and its local validity window is active; this is not effective authorization;
- **Effective T3N access Confirmed**: the authenticated principal's `checkDelegation()` returned `authorised=true` for canonical Tenant DID + exact contract/functions/scopes;
- **Effective T3N access Denied**: T3N returned `authorised=false`; fail closed;
- **Effective T3N access Unknown**: the check failed or was inconclusive; fail closed;
- **resolved**: contract id/version were resolved;
- **authorized**: human business authorization was persisted for the exact action, policy provenance and Executor DID;
- **accepted / pending verification**: the execution endpoint acknowledged the operation; final state is not yet proven;
- **verified**: independent read-back matched the closed expected state;
- **completed**: Spring persisted completion only after verified read-back;
- **unverified**: outcome is ambiguous/not confirmed and no automatic re-execution occurs;
- **execution proof**: short-lived server-to-gateway capability, not hardware attestation;
- **proved live**: matching live evidence/capture exists.

Do not say “guarantees GDPR compliance”, “hardware verified”, “exactly once”, “at most once”, “Member grant proves readiness”, “profile resolution proved live”, “all four scenarios execute end-to-end” or “completed from HTTP 2xx” without corresponding evidence/contract.

This file is the repository source of truth for the public submission narrative and handover model.

## Persistent trust-manifest rollback boundary

Before Tenant, Proposal Agent or Protected Executor identity is authenticated, the gateway verifies the official signed T3N trust manifest and reads the persisted high-water mark for the selected network. If a floor exists, `fetchTrustedManifest(network, { minVersion })` is mandatory. All three sessions share the same `TrustManifestFloorStore`, so one runtime cannot accept separate rollback histories for the same network.

The floor is monotonic and network-scoped: accepting version 101 allows 101 or a later verified version, while version 100 is rejected even after a gateway restart. The state is written atomically to persistent `/data` storage and contains only the network, accepted version and acceptance timestamp. Missing state is valid only for first bootstrap; malformed, truncated or unreadable state fails closed and is never silently reset. Resetting the floor is an explicit operational recovery decision because it discards rollback history.

For judging and evidence, the claims are deliberately separate:

- **Trust anchor VERIFIED**: the signed T3N manifest established the cluster trust boundary used for authentication.
- **Rollback floor PERSISTED**: a valid monotonic manifest-version floor was durably stored and reused across restarts.
- **Trust manifest version**: the observed high-water version associated with that evidence bundle.
- **Member grant state**: configured authorization read-back, not the effective authorization verdict.
- **Effective T3N access state**: the authenticated principal's exact `checkDelegation()` verdict.
- **Policy version/hash**: the exact canonical operational policy provenance used by the contract; not a hardware-attestation statement.
