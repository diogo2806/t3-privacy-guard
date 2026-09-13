# T3 Privacy Guard — Submission & Judge Guide

## Product position

**T3 Privacy Guard is an enterprise trust runtime for AI agents.** Its purpose is not to make the model itself trustworthy. Its purpose is to keep policy, identity, private-data resolution, business authorization, privileged execution and completion proof outside the model even when the model is manipulated.

The product thesis is intentionally simple:

> **AI can propose. Policy decides. Humans authorize. A separate T3N executor performs protected actions. Independent evidence proves the outcome.**

The current challenge implementation applies that pattern to confidential incident response. The Rust policy recognizes four concrete operational actions: credential revocation, account isolation, incident recording and security notification. The Protection demo exposes all four as business-readable presets while preserving the strongest end-to-end execution/read-back path for credential revocation only.

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host`, normal field names and enumerated logical private-data references. It cannot provide a policy decision, DID, override, secret, execution capability or literal T3N profile placeholder.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM policy through the authenticated **Proposal Agent DID** and tenant `pii_did`. That Proposal Agent receives only the `evaluate-action` Member Delegation function and no protected-egress hosts. A malicious exfiltration proposal receives `DENY`. A minimum legitimate proposal can receive `ALLOW`, but `ALLOW` is still not execution: an authenticated operator must explicitly authorize remediation, after which Spring emits a short-lived one-time signed capability bound to the exact action, decision, normal fields, logical private references, policy provenance and canonical **Protected Executor DID**.

The gateway verifies service authentication, capability integrity, expiry, body equality, executor identity and anti-replay state before protected T3N execution. `execute-remediation` and `verify-remediation` use a second T3N credential/session whose canonical DID is different from both the tenant and Proposal Agent DIDs. The Protected Executor receives only those privileged functions plus the minimum required egress hosts and is never used by the AI provider or the proposal path.

For private profile data, the application carries only a category such as `verified_email`. The Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`; the real value can be resolved only by T3N during protected egress and is not returned to React, Java, the model or gateway responses.

Protected credential revocation is fail-safe under retries. Spring creates a persistent atomic claim before egress. The TEE sends `requestId` as the stable idempotency key, but a 2xx only produces `PENDING_VERIFICATION`. A distinct T3N `verify-remediation` read-back by the Protected Executor must observe the matching `operation_id` and the closed expected state `REVOKED` before the business state becomes `COMPLETED`. Ambiguous outcomes become `UNVERIFIED`; they may be re-verified but are never automatically executed again.

The operational policy used by contract `0.4.0` is versioned in private T3N KV. Each decision carries the exact `policyVersion` and deterministic SHA-256 `policyHash`; critical invariants remain compiled in WASM. Missing or invalid policy fails closed. Human authorization and protected execution are bound to the same version/hash and Executor DID so a policy change or silent executor substitution after approval cannot reuse stale authority.

The project reports only verifiable state: `NOT_RUN` never becomes `PASS`, simulated output is not labelled live, profile-placeholder resolution is not labelled proved live until a compatible testnet profile actually executes it, external execution is not labelled completed from HTTP acceptance alone, and hardware attestation is not claimed without a concrete artifact.

## Why this is more than PII detection

A normal PII filter answers questions such as “does this prompt contain an email address?”. T3 Privacy Guard addresses a larger authority problem:

```text
What may the model propose?
        |
Which T3N principal may evaluate that proposal?
        |
Which policy version governs this decision?
        |
Which action/purpose/host/data are allowed?
        |
Which private value may be resolved, and where?
        |
Has a human authorized the exact action and policy provenance?
        |
Which separate T3N principal is authorized to execute/verify it?
        |
Can this exact authorization be replayed or moved to another executor?
        |
Did the external side effect really reach the expected state?
```

A model can therefore remain useful while being structurally unable to grant itself the missing authority. Even compromise of the Proposal Agent credential does not by itself provide the T3N functions delegated to the Protected Executor.

## 60-second judge story

### Attack path

```text
Prompt injection
  -> real model proposes api_key + attacker.example
  -> proposal is persisted as untrusted output
  -> authenticated Proposal Agent DID is added outside the model
  -> Proposal delegation contains evaluate-action only
  -> T3N Rust/WASM loads the active versioned policy
  -> policy evaluates the request
  -> DENY + policy provenance
  -> no human authorization
  -> no protected egress
```

The important observation is not merely that a keyword was detected. The model is allowed to produce the malicious proposal, but **the model does not control the decision boundary and the Proposal Agent does not possess the native T3N execution functions**.

### Legitimate path

```text
Minimum legitimate credential-revocation proposal
  -> Proposal Agent -> T3N policy ALLOW + exact version/hash
  -> authenticated human authorizes exact action + policy provenance
  -> Spring signs one-time capability bound to Protected Executor DID
  -> gateway validates body equality + executor identity + expiry + anti-replay
  -> Protected Executor session invokes execute-remediation
  -> T3N rechecks active version/hash
  -> protected execution
  -> external acknowledgement = PENDING_VERIFICATION
  -> Protected Executor invokes separate read-back
  -> VERIFIED REVOKED
  -> Spring records COMPLETED
```

The important observation is that no single success signal and no single agent principal is trusted to mean more than it proves.

## Current enterprise actions and scenario catalog

The current Rust policy defines these real action contracts, and the dashboard exposes each one as a synthetic demonstration preset:

| Business scenario | Action | Purpose | Allowed normal fields | Private reference | Current demo depth |
|---|---|---|---|---|---|
| Credential compromised | `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none | Policy + human authorization + Protected Executor + independent `REVOKED` read-back |
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

Spring persists the version/hash with the policy decision. Human authorization requires versioned provenance. The one-time remediation capability signs the same version/hash and current Protected Executor DID, the gateway verifies exact body/executor equality, and T3N protected execution re-reads the current private policy before egress. If the policy changed or the executor identity changed after authorization, execution is rejected and the action must be evaluated/authorized again.

The policy hash proves which canonical rules produced a decision; it is **not** hardware attestation.

## Judge quick path

```text
1. Sign in as application operator
2. Read the product thesis before inspecting low-level metadata
3. Confirm Gateway / Tenant / Proposal agent / Protected executor / Contract / both Delegations separately
4. Confirm Proposal delegation = evaluate-action only and no protected-egress hosts
5. Confirm Executor delegation = execute-remediation + verify-remediation and minimum hosts
6. Choose Credential compromised and inspect the synthetic attack prompt
7. Click Ask agent
8. Inspect the real model's structured Agent proposal
9. Observe independent T3N TEE DENY and the exact policy version/hash
10. Switch through Account takeover, Record security incident and Notify security contact
11. Confirm each selection only prepares editable synthetic input and prior results are cleared
12. Use Ask agent and inspect the real proposal + real T3N DENY/REDACT/ALLOW result
13. For Notify security contact, confirm only logical verified_email appears, never plaintext email or raw profile placeholder
14. Return to Credential compromised and prepare the minimum revocation path
15. Observe T3N ALLOW/REDACT and the minimum-data boundary
16. Record explicit human authorization only after ALLOW under the displayed policy version/hash
17. Confirm the authorization is bound to the displayed Protected Executor DID
18. Execute protected credential revocation when synthetic egress/read-back is configured
19. Observe PENDING_VERIFICATION or the verification transition
20. Accept COMPLETED only when independent read-back shows VERIFIED
21. Open Evidence and confirm tenant/proposal/executor DIDs, exact T3N_TESTNET claims, contract/WASM/policy provenance and NOT_RUN boundaries
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
      +--> Proposal Agent session
      |      canonical Proposal Agent DID
      |      Member Delegation: evaluate-action only
      |      allowed_hosts: []
      |                  |
      |                  v
      |           T3N / Rust WASM policy
      |           private KV policy version/hash
      |           DENY | REDACT | ALLOW
      |                            |
      |                    authenticated human
      |                            |
      |                   one-time capability
      |                bound to Executor DID
      |                            |
      +--> Protected Executor session
             canonical Executor DID
             Member Delegation:
             execute-remediation + verify-remediation
             minimum required egress hosts
                              |
                       atomic DB claim
                              |
                    execute-remediation
                              |
                    PENDING_VERIFICATION
                              |
                     verify-remediation
                              |
                  VERIFIED -> COMPLETED
                  otherwise -> UNVERIFIED

Tenant session independently supplies canonical tenant pii_did.
```

Trust model:

- **Prompt is untrusted.** It may contain instruction injection and never becomes an authorization source.
- **Scenario selection is presentation state.** It loads synthetic input and grants no authority.
- **The model is not a security boundary.** It can only call one proposal tool with a closed JSON schema.
- **Unknown or privileged model fields are rejected.** Decisions, overrides, identities, credentials, secrets, API keys and literal `{{profile...}}` markers are rejected before T3N evaluation.
- **Private data is referenced, not copied.** The model/application may request `verified_email`; only Rust/WASM can convert it to the official T3N profile marker.
- **T3N identities are server-derived.** Tenant, Proposal Agent and Protected Executor DIDs come from their authenticated T3N sessions; none is supplied or hardcoded by the model/browser.
- **Proposal authority is least privilege.** Proposal Agent has `evaluate-action` only and no protected-egress hosts.
- **Execution authority is separate.** Protected Executor has a different credential/DID, is never used by the AI provider, and has only `execute-remediation`/`verify-remediation` plus minimum hosts.
- **Rust/WASM owns immutable security invariants.** The model and KV policy cannot manufacture authority or relax forbidden-secret/identity/delegation boundaries.
- **Private T3N KV owns versioned operational rules.** Each accepted decision exposes deterministic version/hash provenance.
- **Spring Boot owns durable business authorization and execution state.** It persists logical refs, policy provenance, the human authorization transition and the remediation state machine.
- **Gateway owns T3N sessions and capability enforcement.** It requires service authentication and validates/consumes the one-time capability, including Executor DID binding, before execution.
- **Private KV owns remediation credentials/endpoints.** The protected credential, action URL and verification URL are not browser inputs.
- **T3N protected egress is the profile-resolution and remediation boundary.** Responses are minimized before returning to application layers.
- **HTTP acceptance is not truth.** Completion is derived from an independent closed read-back, not from the original response code.

## Authority matrix

| Question | Source of authority |
|---|---|
| Which demo context is selected? | Browser presentation state only |
| What did the user ask? | Untrusted prompt |
| What action does the model suggest? | AI proposal |
| Which principal may evaluate the proposal? | Authenticated Proposal Agent session + Proposal Member Delegation |
| Which tenant/data owner is the authorization subject? | Authenticated tenant session |
| Which operational rules are active? | Versioned private T3N KV policy |
| Which critical rules cannot be relaxed? | Rust/WASM invariants |
| Is action/purpose/host/data allowed? | Rust/WASM evaluation of active policy |
| Is business remediation approved? | Authenticated human operator bound to policy provenance |
| Which principal may execute/verify privileged remediation? | Separate authenticated Protected Executor session + Executor Member Delegation |
| Is this exact execution authorized now? | Signed one-time capability bound to current Protected Executor DID |
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
| Remediation capability binds exact policy version/hash and Protected Executor DID | PROVED LOCAL | signer/verifier + remediation tests |
| Executor substitution after human authorization is rejected | PROVED LOCAL | `RemediationAuthorizationSignerTest` + `remediation-authorization.test.ts` |
| Protected execution rejects stale policy provenance | PROVED LOCAL | Rust/gateway remediation tests |
| Literal profile placeholders and unknown private refs are rejected | PROVED LOCAL | proposal schema + Spring validation + Rust policy tests |
| `verified_email` is the only current logical private reference | PROVED LOCAL | Rust policy/remediation mapping |
| `verified_email` is allowed only for `notify-security` / `incident-notification` | PROVED LOCAL | Rust policy tests |
| Rust maps `verified_email` to `{{profile.verified_contacts.email.value}}` | PROVED LOCAL | Rust remediation regression test |
| Java/H2 persists logical refs, not plaintext profile values | PROVED LOCAL | entity/service/API model + tests |
| Human capability binds private refs as well as normal fields | PROVED LOCAL | signer/verifier tests |
| Reflected upstream private value is absent from contract result schema | PROVED LOCAL | Rust remediation regression test |
| Tenant DID derives from authenticated T3N session | PROVED LOCAL | gateway session code/tests |
| Proposal Agent and Protected Executor use separately configured credentials/sessions | PROVED LOCAL | env/session/deployment-manifest tests |
| Proposal grant construction contains `evaluate-action` only and no protected hosts | PROVED LOCAL | live-evidence configuration + gateway tests |
| Executor grant construction contains only execute/verify plus minimum hosts | PROVED LOCAL | live-evidence configuration + gateway tests |
| Three live identities must be distinct before evidence can succeed | PROVED LOCAL | testnet/evidence runner identity check |
| Delegated calls bind `pii_did` to tenant DID | PROVED LOCAL | gateway contract tests |
| Protected remediation requires service auth + signed human capability at the gateway boundary | PROVED LOCAL | gateway authorization boundary/tests |
| Concurrent requests acquire at most one local execution claim | PROVED LOCAL | pessimistic claim + concurrency tests |
| HTTP 2xx cannot directly produce `COMPLETED` | PROVED LOCAL | Rust contract + Java state-machine tests |
| `COMPLETED` requires independent read-back of matching operation/state | PROVED LOCAL | Rust/Java verification tests |
| Timeout/ambiguous ACK does not automatically re-execute | PROVED LOCAL | `IncidentServiceTest` |
| Reload reads persisted execution state without egress/reverification | PROVED LOCAL | `RemediationQueryServiceTest` + frontend API flow |
| T3N directly rejects Proposal Agent `execute-remediation` | NOT CLAIMED until live run | `LIVE-PROPOSAL-CANNOT-EXECUTE` must PASS in testnet evidence |
| T3N directly rejects Proposal Agent `verify-remediation` | NOT CLAIMED until live run | `LIVE-PROPOSAL-CANNOT-VERIFY` must PASS in testnet evidence |
| Real model attack -> T3N DENY on live testnet | NOT CLAIMED | only after matching public capture/evidence run |
| T3N profile placeholder resolves verified email on live testnet | NOT RUN | requires compatible profile/user context and matching evidence |
| Verified external remediation on live testnet | NOT CLAIMED | only after execute + independent verify scenario passes |
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

`private_refs` contains domain-level categories only. The model cannot submit `{{profile...}}`, `profile.*`, a private value, a new private namespace, policy configuration, `agent_did`, `executor_did` or any T3N credential. Provider failure, invalid JSON, missing/multiple tool calls, extra keys or unsafe authority fields fail closed.

## Structural private-data flow

```text
Agent request: verified_email
        |
        v
Spring/H2 stores: verified_email
        |
        v
Proposal Agent -> T3N policy checks action + purpose + host + private ref
        |
        v
Human authorization capability signs privateRefsHash + policy provenance + Executor DID
        |
        v
Gateway verifies exact private_refs + policy version/hash + Executor DID
        |
        v
Protected Executor invokes Rust/WASM
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

If the profile field is unavailable, user context is missing, placeholder is denied, Executor delegation is revoked, the destination host is not authorized or policy provenance no longer matches, execution fails closed. Error text never returns the resolved value.

## Verified remediation flow

The current verified completion flow is specifically the credential-revocation path:

```text
Proposal Agent -> T3N TEE ALLOW for revoke-credential
      | exact policy version/hash
Authenticated operator authorizes
      | same policy provenance + Protected Executor DID
Spring checks persisted action + ALLOW
      |
HMAC capability binds fields + private refs + policy provenance + Executor DID
      |
Atomic pessimistic claim creates EXECUTING
      |
Gateway verifies service token + capability + current Executor identity
      |
Protected Executor -> T3N execute-remediation rechecks active policy version/hash
      | requestId -> Idempotency-Key
      v
PENDING_VERIFICATION + operation_id
      |
Protected Executor -> T3N verify-remediation
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
- a capability issued for Executor A cannot be silently used by Executor B;
- verification outage or contradictory state becomes `UNVERIFIED`;
- `UNVERIFIED` with an operation id can invoke **Verify external state**, which performs read-back only;
- a reload fetches persisted remediation state through a read-only endpoint and does not execute/verify anything.

`requestId` is a stable logical idempotency key. The application prevents duplicate local initiation through its durable claim. It does **not** claim exactly-once or provider-level at-most-once unless the external provider explicitly honors the idempotency key.

## Terminal 3 integration findings

### Member Delegation example and `scopes`

The project validates/sends non-empty scopes even where simplified examples omit them, following the field reference.

### Delegated `pii_did`

Every delegated execution derives `pii_did` internally from `tenantSession.getTenantDid()`. Browser, Java and LLM cannot supply or override the authorization subject.

### Proposal vs Protected Executor authority

The Proposal Agent and Protected Executor are separate authenticated T3N principals. Proposal Member Delegation grants only `evaluate-action` with no protected-egress hosts. Executor Member Delegation grants only `execute-remediation` and `verify-remediation` with the minimum required hosts. Both use canonical DIDs from authenticated sessions; credentials and DIDs are not hardcoded or copied from configuration text.

The application-level human capability is retained as a second barrier and is bound to the current Executor DID. The live adversarial runner attempts both privileged functions directly with the Proposal Agent session and records `PASS` only for recognizable T3N authorization/delegation rejection.

### Profile placeholders

The application never lets the LLM/browser choose a raw placeholder. `verified_email` is mapped inside the TEE contract to the documented `profile.verified_contacts.email.value` marker, limiting the public application contract to an auditable domain vocabulary.

### Versioned private policy

Operational rules are provisioned to private T3N KV under immutable version snapshots and selected through the `current` pointer. The canonical policy SHA-256 is carried as provenance across evaluation, authorization, evidence and protected execution. Policy rollback is explicit; a hash is not described as attestation.

### Remediation verification

The contract exposes separate `execute-remediation` and `verify-remediation` functions. Only the Protected Executor delegation includes both when required. Evidence orchestration derives the allowed HTTPS hosts from the configured remediation and verification endpoints rather than broadening the grant arbitrarily.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new tenant, Proposal Agent and Protected Executor credentials, operator credentials, provider key, service/capability keys and persistent gateway `/data`. Existing private keys are not transferred through GitHub/UI. Profile-backed live evidence must use a dedicated test profile with synthetic data.

## Evidence model

```text
WASM bytes -> SHA-256 -> deployment-manifest.json
policy doc -> SHA-256 ---------|
                               +-> same tenant/proposal/executor DIDs / contract / version / WASM hash / policy version+hash
                                            |
                                            v
                                     testnet-run.json
```

`PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means the scenario was not executed and is never counted as success. The profile-placeholder execution scenario remains `NOT_RUN` until a compatible profile/user context exists; local tests do not upgrade that claim to live proof.

The live least-privilege negative evidence is explicit:

```text
Proposal Agent direct execute-remediation -> must be rejected by T3N
Proposal Agent direct verify-remediation  -> must be rejected by T3N
```

An unrelated configuration, transport or missing-secret failure is not accepted as proof of delegation enforcement.

The live remediation scenario is stricter:

```text
attack DENY + policy provenance
   -> Protected Executor execute-remediation with same policy provenance
   -> PENDING_VERIFICATION
   -> operation_id present
   -> Protected Executor verify-remediation VERIFIED
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

When preparing egress evidence, configure `SECURITY_API_URL` and the separate `SECURITY_VERIFICATION_URL`. Both are sealed into the private map, and the **Executor** delegation host allowlist is derived from those HTTPS endpoints; the Proposal delegation has no protected-egress hosts. Generated metadata is leak-scanned for operator credentials, tenant/proposal/executor T3N keys, AI provider key, service token, capability signing key, remediation key and configured sentinel. Evidence metadata also carries the exact policy version/hash and all three canonical DIDs used by the run.

## Screenshot shot list

Screenshots must tell the same authority-separation story as the product, not merely prove that screens exist.

1. Product header + live T3N operational status.
2. Technical details showing distinct Tenant DID, Proposal Agent DID and Protected Executor DID.
3. Proposal delegation showing `evaluate-action` only and Executor delegation showing only execute/verify plus minimum hosts.
4. Four enterprise scenario cards with Credential compromised selected and the statement that presets are not permissions.
5. Attack prompt + provider/model provenance + model proposal + `DENY` + policy version/hash.
6. `REDACT` data-minimization evidence.
7. Notify security contact selected, showing logical `verified_email` and no plaintext address/raw placeholder.
8. Private-reference panel showing `Verified email`, Agent plaintext `NO`, Java plaintext `NO`, T3N egress resolution boundary.
9. Legitimate credential-revocation proposal/minimum remediation + `ALLOW` + policy provenance.
10. Human authorization separate from execution and bound to the same version/hash and Protected Executor identity.
11. Execution/verification panel showing the state machine.
12. Verified remediation screenshot only after `Verification = VERIFIED` and `Final state = COMPLETED`.
13. Evidence Center with tenant/proposal/executor identities, T3N_TESTNET metadata/results, contract/WASM/policy provenance and optional scenarios honestly PASS/FAIL/NOT RUN.

Never capture passwords, cookies, tenant/Proposal/Executor T3N keys, provider key, service/capability keys, remediation secret, resolved profile PII, `.env` or raw logs.

## Demo video storyboard

```text
0–10s    Product thesis: AI proposes; it does not own authority
10–25s   Show Tenant / Proposal Agent / Protected Executor as distinct T3N principals
25–40s   Show Proposal delegation evaluate-only vs Executor execute+verify delegation
40–60s   Show four enterprise presets and explain that selection grants no authority
60–85s   Credential attack prompt -> real provider -> malicious structured proposal
85–105s  Independent T3N TEE DENY + policy provenance; no protected egress
105–125s Switch scenarios; show isolation, record incident and logical verified_email notification context
125–145s Minimum credential-revocation request -> ALLOW/REDACT + policy version/hash
145–160s Explicit human authorization bound to policy provenance + Protected Executor DID
160–175s Protected Executor -> PENDING_VERIFICATION -> independent read-back
175–180s Evidence Center -> exact proof status and NOT_RUN boundaries
```

## UX and claim wording rules

The submission must lead with user/business meaning, then expose the technical proof. Technical labels remain precise.

- **enterprise scenario**: synthetic demonstration context and prompt preset, never a permission or policy decision;
- **agent proposal**: model-produced structured request, not authorization;
- **Proposal Agent**: authenticated T3N principal used for `evaluate-action`; it has no native execution/verification grant;
- **Protected Executor**: separate authenticated T3N principal used only for privileged execute/verify operations after application authorization;
- **Proposal delegation**: Member Delegation for `evaluate-action` only, with no protected-egress hosts;
- **Executor delegation**: independent Member Delegation for `execute-remediation`/`verify-remediation` plus minimum required hosts;
- **policy version**: immutable operational ruleset identifier loaded from private T3N KV;
- **policy hash**: deterministic canonical SHA-256 proving policy provenance, not hardware attestation;
- **logical private reference**: category such as `verified_email`, not the private value;
- **resolved by T3N at egress**: only claim for executions where T3N actually resolved the placeholder;
- **authenticated**: a session identity was authenticated;
- **resolved**: contract id/version were resolved;
- **delegated**: an active member grant was observed for that specific principal;
- **scheduled**: a grant exists but its `valid_from_secs` is still in the future; it is not operational;
- **authorized**: human business authorization was persisted for the exact action, policy provenance and current Protected Executor identity;
- **accepted / pending verification**: the execution endpoint acknowledged the operation; final state is not yet proven;
- **verified**: independent read-back matched the closed expected state;
- **completed**: Spring persisted completion only after verified read-back;
- **unverified**: outcome is ambiguous/not confirmed and no automatic re-execution occurs;
- **execution proof**: short-lived server-to-gateway capability, not hardware attestation;
- **proved live**: matching live evidence/capture exists.

Do not say “guarantees GDPR compliance”, “hardware verified”, “exactly once”, “at most once”, “profile resolution proved live”, “Proposal Agent direct privileged call is proved rejected”, “all four scenarios execute end-to-end” or “completed from HTTP 2xx” without corresponding evidence/contract.

This file is the repository source of truth for the public submission narrative and handover model.

## Persistent trust-manifest rollback boundary

Before any of the three T3N principals is authenticated, the gateway verifies the official signed trust manifest and reads the persisted high-water mark for the selected network. If a floor exists, `fetchTrustedManifest(network, { minVersion })` is mandatory. Tenant, Proposal Agent and Protected Executor sessions share the same `TrustManifestFloorStore`, so one runtime cannot accept separate rollback histories for the same network.

The floor is monotonic and network-scoped: accepting version 101 allows 101 or a later verified version, while version 100 is rejected even after a gateway restart. The state is written atomically to persistent `/data` storage and contains only the network, accepted version and acceptance timestamp. Missing state is valid only for first bootstrap; malformed, truncated or unreadable state fails closed and is never silently reset. Resetting the floor is an explicit operational recovery decision because it discards rollback history.

For judging and evidence, the claims are deliberately separate:

- **Trust anchor VERIFIED**: the signed T3N manifest established the cluster trust boundary used for authentication.
- **Rollback floor PERSISTED**: a valid monotonic manifest-version floor was durably stored and reused across restarts.
- **Trust manifest version**: the observed high-water version associated with that evidence bundle.
- **Policy version/hash**: the exact canonical operational policy provenance used by the contract; not a hardware-attestation statement.
- **Hardware attestation**: not implied by any of the states above and not claimed without a separate execution-specific artifact.

The Evidence Center exposes those sanitized states and the Manual da Tela explains the expected failure cases (`TRUST MANIFEST UNAVAILABLE`, `ROLLBACK REJECTED`, `TRUST FLOOR CORRUPTED`, `VERSION NOT EXPOSED BY SDK`) together with policy-KV fail-closed states without exposing trust-manifest contents, policy secrets or credentials.

## Public Proposal Agent onboarding and independent Activity provenance

The current gateway completes the public Proposal Agent onboarding story without conflating identity, discoverability and authorization. The Protected Executor is deliberately a separate principal and is not made to look like the public proposal Agent Card.

```text
separate Proposal Agent credential
      |
      v
AgentSession authentication
      |
      v
canonical Proposal Agent DID
      |
      +--> Agent Card hosted by T3N
      |      |
      |      v
      |    read-only public resolution
      |      |
      |      v
      |    REGISTERED / NOT_REGISTERED / MISMATCH / UNAVAILABLE
      |
      v
Proposal Member Delegation
      |
      v
evaluate-action authority only

separate Protected Executor credential
      |
      v
ExecutorSession authentication
      |
      v
canonical Executor DID
      |
      v
Executor Member Delegation
      |
      v
execute-remediation + verify-remediation authority only
```

The generated Agent Card is derived from the DID returned by the authenticated Proposal Agent session, not from a configured/hardcoded DID. It advertises only the supported `DID` service for that same identity, is bounded to the hosted-card size limit and rejects sensitive metadata/private-key-shaped values. The implementation does not advertise unsupported A2A/MCP services or x402 payment capability. `REGISTERED` therefore means only that the public card resolved and matched the authenticated Proposal Agent DID and closed service schema. It does not mean `DELEGATED`, `AUTHORIZED`, TEE-attested, allowed to access private data, or that the Protected Executor shares the same identity.

Operational commands are intentionally split:

```bash
cd t3n-gateway
npm run agent:card:verify    # read-only Proposal Agent registry verification
npm run agent:card:publish   # explicit mutable host-card operation; may consume credits
```

The Evidence Center/status surface can show the observed onboarding state together with the separate Executor identity/delegation state. The deployment manifest may contain the public Proposal Agent card URI, SHA-256 of the exact resolved card, verification timestamp and service names plus the sanitized canonical Executor DID. Those fields are provenance; the hash/DID are not permissions or attestation claims.

The judge should explicitly read these controls as different:

```text
Proposal Agent AUTHENTICATED     -> proposal-session/key identity proved
Proposal Agent REGISTERED        -> public Agent Card resolved for that DID
Proposal delegation ACTIVE       -> tenant granted evaluate-action only
Protected Executor AUTHENTICATED -> separate executor-session/key identity proved
Executor delegation ACTIVE       -> tenant granted execute/verify restrictions
Human authorization              -> exact business action + provenance + Executor DID approved
```

The audit story also has two independent sources. Local business audit records application events such as human authorization. For T3N-observed functions, the application can read the official Activity Log through an authenticated, bounded gateway path and reconcile exact network provenance using T3N sequence + activity hash + function metadata. Evaluation activity is attributed to the Proposal Agent DID; execute/verify activity is attributed to the Protected Executor DID. Timestamp proximity is not used as identity.

Reconciliation states mean:

- `MATCHED`: local network-backed event matches the observed T3N sequence/hash/function;
- `LOCAL_ONLY`: event is intentionally local and has no T3N function;
- `T3N_ONLY`: relevant T3N activity exists without a corresponding local event in the bounded result;
- `UNMATCHED`: local event expects T3N provenance but exact network provenance was not verified.

If the Activity Log is unavailable, the local audit remains visible but network provenance is explicitly unavailable. If the bounded T3N page is truncated, the result is marked incomplete and unmatched entries are not treated as proof that no T3N event exists. The two evidence dimensions should be read independently:

```text
Local business history     application audit
T3N operation provenance   official Activity Log reconciliation
```

Updated judge sequence for identity/provenance:

```text
1. Confirm Tenant AUTHENTICATED.
2. Confirm Proposal Agent AUTHENTICATED and note its canonical DID.
3. Inspect Proposal Agent onboarding separately: REGISTERED is desirable evidence, negative states remain visible.
4. Confirm Proposal delegation ACTIVE and restricted to evaluate-action.
5. Confirm Protected Executor AUTHENTICATED with a different canonical DID.
6. Confirm Executor delegation ACTIVE and restricted to execute/verify plus minimum hosts.
7. In Evidence, compare Agent Card DID/hash metadata with the authenticated Proposal Agent DID and separately inspect Executor DID.
8. After policy/remediation activity, inspect Business Audit Trail and T3N reconciliation separately.
9. Treat MATCHED as exact network provenance for the associated T3N-backed event, not as proof that every local business event occurred on T3N.
```

Additional claim matrix entries:

| Claim | Current status | Source of truth |
|---|---|---|
| Agent Card builder uses only the canonical authenticated Proposal Agent DID | PROVED LOCAL | `agent-card.ts` + tests |
| Agent Card rejects sensitive metadata and unsupported services | PROVED LOCAL | `agent-card.test.ts` |
| Public card resolution distinguishes REGISTERED/NOT_REGISTERED/MISMATCH/UNAVAILABLE | PROVED LOCAL | `AgentCardRegistry` + tests |
| Registered Proposal Agent Card is kept distinct from both Member Delegations and human authorization | PROVED LOCAL | status/evidence/frontend tests |
| Deployment evidence records Proposal Agent Card provenance and Executor DID without exposing credentials | PROVED LOCAL | deployment manifest + leak tests |
| Public Proposal Agent Card is actually registered on a live T3N environment | OBSERVED ONLY WHEN REGISTERED | read-only live registry result in the evidence/status metadata |
| Activity actor DID distinguishes Proposal Agent evaluation from Protected Executor execute/verify | PROVED LOCAL | contract activity capture + reconciliation path |
| T3N Activity reconciliation requires exact sequence/hash/function plus tenant/actor/contract boundary | PROVED LOCAL | `AuditEvidenceService` + tests |
| Activity Log unavailability does not fabricate MATCHED network provenance | PROVED LOCAL | degraded reconciliation tests |

Screenshot/video additions when live registration is available:

- show `Proposal agent AUTHENTICATED`, `Agent onboarding REGISTERED`, `Proposal delegation ACTIVE`, `Protected executor AUTHENTICATED`, and `Executor delegation ACTIVE` together so their different meanings are visible;
- capture the Evidence Center Agent Card URI/hash only if it contains no secret and is the observed public proposal card;
- show the distinct Executor DID without exposing its credential;
- show the audit reconciliation summary with `MATCHED`, `LOCAL_ONLY`, `T3N_ONLY` or `UNMATCHED` as observed, without forcing all rows to look successful.

Never claim “registered = authorized”, “Agent Card = executor identity”, “Agent Card = attestation”, “Proposal grant includes execution”, “all audit events are on-chain/on-T3N”, or “MATCHED” when the official Activity Log was unavailable or incomplete.
