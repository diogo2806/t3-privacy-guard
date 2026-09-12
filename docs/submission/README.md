# T3 Privacy Guard — Submission & Judge Guide

## Product position

**T3 Privacy Guard is an enterprise trust runtime for AI agents.** Its purpose is not to make the model itself trustworthy. Its purpose is to keep policy, identity, private-data resolution, business authorization and completion proof outside the model even when the model is manipulated.

The product thesis is intentionally simple:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

The current challenge implementation applies that pattern to confidential incident response. The versioned operational policy recognizes four concrete actions: credential revocation, account isolation, incident recording and security notification. The dashboard currently emphasizes the adversarial credential-remediation flow because it exercises the strongest end-to-end controls in one scenario.

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host`, normal field names and enumerated logical private-data references. It cannot provide a policy decision, DID, override, secret, execution capability, operational policy document or literal T3N profile placeholder.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM contract through the authenticated Agent DID and tenant `pii_did`. The contract loads the active operational rules from private T3N KV, validates them against compiled security invariants and returns `DENY`, `REDACT` or `ALLOW` together with the exact policy version and canonical SHA-256 hash used. A malicious exfiltration proposal receives `DENY`. A minimum legitimate proposal can receive `ALLOW`, but `ALLOW` is still not execution: an authenticated operator must explicitly authorize remediation when required, after which Spring emits a short-lived one-time signed capability bound to the exact action, decision, normal fields, logical private references and policy version/hash. The gateway verifies service authentication, capability integrity, expiry, body equality, policy provenance and anti-replay state before protected T3N execution.

For private profile data, the application carries only a category such as `verified_email`. The Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`; the real value can be resolved only by T3N during protected egress and is not returned to React, Java, the model or gateway responses.

Protected execution is fail-safe under retries. Spring creates a persistent atomic claim before egress. The TEE sends `requestId` as the stable idempotency key, but a 2xx only produces `PENDING_VERIFICATION`. A distinct T3N `verify-remediation` read-back must observe the matching `operation_id` and the closed expected state `REVOKED` before the business state becomes `COMPLETED`. Ambiguous outcomes become `UNVERIFIED`; they may be re-verified but are never automatically executed again.

The project reports only verifiable state: `NOT_RUN` never becomes `PASS`, simulated output is not labelled live, profile-placeholder resolution is not labelled proved live until a compatible testnet profile actually executes it, external execution is not labelled completed from HTTP acceptance alone, policy version/hash are not described as hardware attestation, and hardware attestation is not claimed without a concrete artifact.

## Why this is more than PII detection

A normal PII filter answers questions such as “does this prompt contain an email address?”. T3 Privacy Guard addresses a larger authority problem:

```text
What may the agent propose?
        |
Who is the authenticated agent?
        |
Which versioned policy is active?
        |
Which action/purpose/host/data are allowed?
        |
Which private value may be resolved, and where?
        |
Has a human authorized the exact action and policy provenance?
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
  -> authenticated Agent DID is added outside the model
  -> Rust/WASM loads active policy from private T3N KV
  -> compiled secret invariant rejects api_key
  -> DENY + exact policy version/hash
  -> no human authorization
  -> no protected egress
```

The important observation is not merely that a keyword was detected. The model is allowed to produce the malicious proposal, but **the model does not control the decision boundary or operational policy**.

### Legitimate path

```text
Minimum legitimate proposal
  -> active T3N KV policy + WASM invariants -> ALLOW
  -> policy version/hash persisted with decision
  -> authenticated human authorizes exact action
  -> Spring signs one-time capability including policy provenance
  -> gateway validates body equality + expiry + anti-replay
  -> contract re-reads policy and rejects stale version/hash
  -> T3N protected execution
  -> external acknowledgement = PENDING_VERIFICATION
  -> separate read-back
  -> VERIFIED REVOKED
  -> Spring records COMPLETED
```

The important observation is that no single success signal is trusted to mean more than it proves.

## Current enterprise actions

The default operational policy defines these action contracts:

| Action | Purpose | Allowed normal fields | Private reference |
|---|---|---|---|
| `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none |
| `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none |
| `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none |
| `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `verified_email` allowed |

The challenge UI currently spotlights credential revocation because it demonstrates policy enforcement, explicit authorization, protected egress, replay resistance and independent completion verification in a single path. The other policy actions are not presented here as broader vertical products that have already been built.

## Versioned operational policy and immutable invariants

Contract `0.4.0` separates enterprise-operational rules from security invariants. The source policy document is canonicalized and provisioned to the private tenant T3N KV map `privacy-guard-policy`. The TEE reads key `current` for each evaluation. The browser, Java backend and AI provider never supply the policy authority used for a decision.

Configurable policy fields are intentionally narrow:

- enabled actions;
- action purpose;
- allowed hosts;
- allowed normal fields;
- allowed logical private references from the contract vocabulary;
- `requires_host`;
- `requires_human_authorization`.

The following remain compiled in Rust/WASM and cannot be relaxed by policy data:

- input and policy size/count limits;
- fail-closed behavior for missing/corrupt policy;
- canonical normalization and duplicate rejection;
- safe host format validation;
- authenticated T3N identity/delegation boundaries;
- rejection of client/model-supplied decision or policy authority;
- closed private-reference vocabulary;
- forbidden secret classes including `api_key`, `token`, `password`, `private_key` and equivalent high-risk fields.

Provisioning is explicit and reproducible:

```text
policy/privacy-guard-policy.json
        |
        v
local schema + invariant validation
        |
        v
canonical JSON -> SHA-256
        |
        v
T3N KV version:<version> immutable snapshot
        |
        v
T3N KV current
        |
        v
read-back -> version/hash equality
        |
        v
history:<timestamp>:<hash-prefix> audit record
```

The same version cannot be republished with different canonical content. A changed rule must receive a new version. Rollback is never an implicit overwrite: the operator supplies `T3N_POLICY_ROLLBACK_VERSION`, the setup command loads only an already persisted immutable `version:<version>` snapshot, updates `current`, verifies read-back and records previous/target version and hash.

`policyVersion` and `policyHash` flow through gateway, Spring persistence/API, human authorization, remediation execution, live evidence and the React decision/evidence UI. Protected remediation re-reads the active policy inside WASM and fails if its exact version/hash differs from what the operator authorized. These values are policy provenance, **not** hardware attestation.

## Judge quick path

```text
1. Sign in as application operator
2. Read the product thesis before inspecting low-level metadata
3. Confirm Gateway / Tenant / Agent / Contract / Delegation separately
4. Inspect the attack prompt
5. Click Run attack scenario
6. Inspect the real model's structured Agent proposal
7. Observe independent T3N TEE DENY plus policy version/hash
8. Submit a legitimate prompt or prepare the minimum safe action
9. Observe T3N ALLOW/REDACT, policy provenance and logical private-data boundary
10. Record explicit human authorization only after ALLOW
11. Execute protected remediation when synthetic egress/read-back is configured
12. Observe PENDING_VERIFICATION or the verification transition
13. Accept COMPLETED only when independent read-back shows VERIFIED
14. Open Evidence and confirm exact T3N_TESTNET claims, policy provenance and NOT_RUN boundaries
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
      | authenticated Agent DID + tenant pii_did
      v
T3N / Rust WASM contract
      | reads private versioned policy from T3N KV
      v
   DENY | REDACT | ALLOW + version/hash
                    |
            authenticated human
                    |
             one-time capability
                    |
             atomic DB claim
                    |
             execute-remediation
                    | re-check exact active version/hash
                    v
             PENDING_VERIFICATION
                    |
              verify-remediation
                    |
          VERIFIED -> COMPLETED
          otherwise -> UNVERIFIED
```

Trust model:

- **Prompt is untrusted.** It may contain instruction injection and never becomes an authorization source.
- **The model is not a security boundary.** It can only call one proposal tool with a closed JSON schema.
- **Unknown or privileged model fields are rejected.** Decisions, overrides, identities, credentials, secrets, API keys, policy documents and literal `{{profile...}}` markers are rejected before T3N evaluation.
- **Private data is referenced, not copied.** The model/application may request `verified_email`; only Rust/WASM can convert it to the official T3N profile marker.
- **T3N identities are server-derived.** Agent DID comes from the authenticated agent session; tenant `pii_did` from the authenticated tenant session.
- **T3N KV owns versioned operational configuration; Rust/WASM owns enforcement.** KV can change business allowlists, but cannot disable compiled secret, identity, schema or fail-closed invariants.
- **Spring Boot owns durable business authorization and execution state.** It persists logical refs, policy provenance, the human authorization transition and the remediation state machine.
- **Gateway owns T3N sessions and privileged execution.** It requires service authentication and validates/consumes the one-time capability before execution.
- **Private KV owns remediation credentials/endpoints.** The protected credential, action URL and verification URL are not browser inputs.
- **T3N protected egress is the profile-resolution and remediation boundary.** Responses are minimized before returning to application layers.
- **HTTP acceptance is not truth.** Completion is derived from an independent closed read-back, not from the original response code.

## Authority matrix

| Question | Source of authority |
|---|---|
| What did the user ask? | Untrusted prompt |
| What action does the model suggest? | AI proposal |
| Which agent identity is executing? | Authenticated T3N Agent session |
| Which tenant/data owner is the authorization subject? | Authenticated tenant session |
| Which operational rules are active? | Versioned private T3N KV policy |
| Can the configured rules violate secret/identity/schema invariants? | No; Rust/WASM compiled invariants remain authoritative |
| Is action/purpose/host/data allowed? | Rust/WASM evaluation of active policy |
| Is business remediation approved? | Authenticated human operator |
| Is this exact execution authorized now? | Signed one-time capability bound to policy version/hash |
| May a private value be resolved? | Closed Rust mapping + T3N protected boundary |
| Did the side effect complete? | Independent read-back + Spring state machine |

## Security claims matrix

| Claim | Current status | Source of truth |
|---|---|---|
| Real configured model produces structured proposals | PROVED LOCAL | provider adapter + agent/backend tests |
| Tool schema cannot accept decision/override/DID/secret/policy authority fields | PROVED LOCAL | proposal schema + policy boundary tests |
| Literal profile placeholders and unknown private refs are rejected | PROVED LOCAL | proposal schema + Spring validation + Rust policy tests |
| `verified_email` is the only current logical private reference | PROVED LOCAL | Rust policy/remediation mapping |
| `verified_email` is allowed only where the active policy permits it and the contract recognizes it | PROVED LOCAL | versioned policy + Rust invariant tests |
| Rust maps `verified_email` to `{{profile.verified_contacts.email.value}}` | PROVED LOCAL | Rust remediation regression test |
| Java/H2 persists logical refs, not plaintext profile values | PROVED LOCAL | entity/service/API model + tests |
| Operational policy hash is deterministic for canonical content | PROVED LOCAL | `policy-document.test.ts` + Rust canonicalization tests |
| Same policy version cannot be republished with different canonical content | PROVED LOCAL | immutable-version validation tests + setup command |
| Missing/corrupt operational policy fails closed | PROVED LOCAL | Rust policy tests |
| External policy cannot allow contract-forbidden secret fields | PROVED LOCAL | Rust + gateway policy validation tests |
| Decision persists the exact policy version/hash used | PROVED LOCAL | gateway/backend/frontend propagation tests |
| Human capability binds policy version/hash and private refs | PROVED LOCAL | signer/verifier tests |
| Active policy change after authorization blocks protected remediation | PROVED LOCAL | Rust remediation binding + Spring/gateway tests |
| Reflected upstream private value is absent from contract result schema | PROVED LOCAL | Rust remediation regression test |
| Tenant DID derives from authenticated T3N session | PROVED LOCAL | gateway session code/tests |
| Agent uses separate credential/DID | PROVED LOCAL | agent/tenant session separation |
| Delegated calls bind `pii_did` to tenant DID | PROVED LOCAL | gateway contract tests |
| Protected remediation requires service auth + signed human capability | PROVED LOCAL | gateway authorization boundary/tests |
| Concurrent requests acquire at most one local execution claim | PROVED LOCAL | pessimistic claim + concurrency tests |
| HTTP 2xx cannot directly produce `COMPLETED` | PROVED LOCAL | Rust contract + Java state-machine tests |
| `COMPLETED` requires independent read-back of matching operation/state | PROVED LOCAL | Rust/Java verification tests |
| Timeout/ambiguous ACK does not automatically re-execute | PROVED LOCAL | `IncidentServiceTest` |
| Reload reads persisted execution state without egress/reverification | PROVED LOCAL | `RemediationQueryServiceTest` + frontend API flow |
| Real model attack -> T3N DENY on live testnet | NOT CLAIMED | only after matching public capture/evidence run |
| Versioned policy setup/read-back on live T3N | NOT CLAIMED unless matching evidence exists | deployment manifest + live run policy metadata |
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

`private_refs` contains domain-level categories only. The model cannot submit `{{profile...}}`, `profile.*`, a private value, a policy document or a new private namespace. Provider failure, invalid JSON, missing/multiple tool calls, extra keys or unsafe authority fields fail closed.

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
Gateway verifies exact private_refs set + policy version/hash
        |
        v
Rust/WASM re-checks active policy and maps verified_email
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

If the profile field is unavailable, user context is missing, placeholder is denied, delegation is revoked, policy is missing/corrupt/stale or the destination host is not authorized, execution fails closed. Error text never returns the resolved value.

## Verified remediation flow

```text
T3N TEE ALLOW + policy version/hash
      |
Authenticated operator authorizes
      |
Spring checks persisted action + ALLOW + provenance
      |
HMAC capability binds fields + private refs + policy version/hash
      |
Atomic pessimistic claim creates EXECUTING
      |
Gateway verifies service token + capability
      |
TEE re-reads current policy and verifies exact binding
      |
T3N execute-remediation
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
- policy version/hash mismatch between authorization and execution is rejected before protected egress;
- verification outage or contradictory state becomes `UNVERIFIED`;
- `UNVERIFIED` with an operation id can invoke **Verify external state**, which performs read-back only;
- a reload fetches persisted remediation state through a read-only endpoint and does not execute/verify anything.

`requestId` is a stable logical idempotency key. The application prevents duplicate local initiation through its durable claim. It does **not** claim exactly-once or provider-level at-most-once unless the external provider explicitly honors the idempotency key.

## Terminal 3 integration findings

### Member Delegation example and `scopes`

The project validates/sends non-empty scopes even where simplified examples omit them, following the field reference.

### Delegated `pii_did`

Every delegated execution derives `pii_did` internally from `tenantSession.getTenantDid()`. Browser, Java and LLM cannot supply or override the authorization subject.

### Profile placeholders

The application never lets the LLM/browser choose a raw placeholder. `verified_email` is mapped inside the TEE contract to the documented `profile.verified_contacts.email.value` marker, limiting the public application contract to an auditable domain vocabulary.

### Versioned operational policy

The policy map is private and read inside the contract. Provisioning validates locally, computes the same canonical SHA-256 model used by Rust, stores an immutable version snapshot, activates `current`, reads it back and verifies version/hash. Rollback references a stored snapshot explicitly and records a history entry. The operational document never contains remediation secrets.

### Remediation verification

The contract exposes separate `execute-remediation` and `verify-remediation` functions. Live delegation includes both only when required. Evidence orchestration derives the allowed HTTPS hosts from the configured remediation and verification endpoints rather than broadening the grant arbitrarily.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new tenant/agent credentials, operator credentials, provider key, service/capability keys and persistent gateway `/data`. Existing private keys are not transferred through GitHub/UI. Operational policy changes use a new version and the T3N KV provisioning command instead of recompiling WASM for ordinary host/field/purpose changes. Profile-backed live evidence must use a dedicated test profile with synthetic data.

## Evidence model

```text
WASM bytes -> SHA-256 -> deployment-manifest.json
                         |
active policy -> version/hash
                         |
                         +-> same DIDs / contract / version / WASM hash / policy hash
                                      |
                                      v
                               testnet-run.json
```

`PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means the scenario was not executed and is never counted as success. The profile-placeholder execution scenario remains `NOT_RUN` until a compatible profile/user context exists; local tests do not upgrade that claim to live proof.

The live remediation scenario is stricter:

```text
attack DENY + policy provenance
   -> execute-remediation PENDING_VERIFICATION with same policy provenance
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
npm run contract:setup-policy
npm run evidence:live
```

When preparing egress evidence, configure `SECURITY_API_URL` and the separate `SECURITY_VERIFICATION_URL`. Both are sealed into the private map, and the delegation host allowlist is derived from those HTTPS endpoints. Generated metadata is leak-scanned for operator credentials, T3N keys, AI provider key, service token, capability signing key, remediation key and configured sentinel. The live evidence manifest also records the active policy version/hash and rejects a run whose policy provenance does not match deployment metadata.

## Screenshot shot list

Screenshots must tell the same authority-separation story as the product, not merely prove that screens exist.

1. Product header + live T3N operational status.
2. Attack prompt + provider/model provenance + model proposal + `DENY`.
3. T3N policy decision with exact policy version/hash and human-authorization requirement.
4. `REDACT` data-minimization evidence.
5. Private-reference panel showing `Verified email`, Agent plaintext `NO`, Java plaintext `NO`, T3N egress resolution boundary.
6. Legitimate proposal/minimum remediation + `ALLOW`.
7. Human authorization separate from execution and bound to policy provenance.
8. Execution/verification panel showing the state machine.
9. Verified remediation screenshot only after `Verification = VERIFIED` and `Final state = COMPLETED`.
10. Evidence Center with T3N_TESTNET contract + policy metadata/results and optional scenarios honestly PASS/FAIL/NOT RUN.

Never capture passwords, cookies, T3N keys, provider key, service/capability keys, remediation secret, resolved profile PII, `.env` or raw logs.

## Demo video storyboard

```text
0–10s    Product thesis: AI proposes; it does not own authority
10–25s   Show authenticated tenant/agent/contract/delegation
25–50s   Attack prompt -> real provider -> malicious structured proposal
50–70s   Independent T3N TEE DENY + exact policy version/hash; no protected egress
70–95s   Show logical private reference instead of private value
95–115s  Minimum legitimate request -> ALLOW/REDACT + same provenance model
115–130s Explicit human authorization bound to policy version/hash
130–150s Protected execution -> accepted/PENDING_VERIFICATION
150–165s Independent read-back -> VERIFIED/COMPLETED when available
165–180s Evidence Center -> exact contract/policy proof status and NOT_RUN boundaries
```

## UX and claim wording rules

The submission must lead with user/business meaning, then expose the technical proof. Technical labels remain precise.

- **agent proposal**: model-produced structured request, not authorization;
- **logical private reference**: category such as `verified_email`, not the private value;
- **policy version/hash**: deterministic provenance for the operational rules actually applied, not hardware attestation;
- **resolved by T3N at egress**: only claim for executions where T3N actually resolved the placeholder;
- **authenticated**: a session identity was authenticated;
- **resolved**: contract id/version were resolved;
- **delegated**: an active member grant was observed;
- **authorized**: human business authorization was persisted for the exact approved action and policy provenance;
- **accepted / pending verification**: the execution endpoint acknowledged the operation; final state is not yet proven;
- **verified**: independent read-back matched the closed expected state;
- **completed**: Spring persisted completion only after verified read-back;
- **unverified**: outcome is ambiguous/not confirmed and no automatic re-execution occurs;
- **execution proof**: short-lived server-to-gateway capability, not hardware attestation;
- **proved live**: matching live evidence/capture exists.

Do not say “guarantees GDPR compliance”, “hardware verified”, “exactly once”, “at most once”, “profile resolution proved live”, “policy hash is attestation” or “completed from HTTP 2xx” without corresponding evidence/contract.

This file is the repository source of truth for the public submission narrative and handover model.
