# T3 Privacy Guard — Submission & Judge Guide

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host`, normal field names and enumerated logical private-data references. It cannot provide a policy decision, DID, override, secret, execution capability or literal T3N profile placeholder.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM policy through the authenticated Agent DID and tenant `pii_did`. A malicious exfiltration proposal receives `DENY`. A minimum legitimate proposal can receive `ALLOW`, but `ALLOW` is still not execution: an authenticated operator must explicitly authorize remediation, after which Spring emits a short-lived one-time signed capability bound to the exact action, decision, normal fields and logical private references. The gateway verifies service authentication, capability integrity, expiry, body equality and anti-replay state before protected T3N execution.

For private profile data, the application carries only a category such as `verified_email`. The Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`; the real value can be resolved only by T3N during protected egress and is not returned to React, Java, the model or gateway responses.

Protected execution is also fail-safe under retries. Spring creates a persistent atomic claim before egress. The TEE sends `requestId` as the stable idempotency key, but a 2xx only produces `PENDING_VERIFICATION`. A distinct T3N `verify-remediation` read-back must observe the matching `operation_id` and the closed expected state `REVOKED` before the business state becomes `COMPLETED`. Ambiguous outcomes become `UNVERIFIED`; they may be re-verified but are never automatically executed again.

The project reports only verifiable state: `NOT_RUN` never becomes `PASS`, simulated output is not labelled live, profile-placeholder resolution is not labelled proved live until a compatible testnet profile actually executes it, external execution is not labelled completed from HTTP acceptance alone, and hardware attestation is not claimed without a concrete artifact.

## Judge quick path

```text
1. Sign in as application operator
2. Confirm Gateway / Tenant / Agent / Contract / Delegation separately
3. Inspect the attack prompt
4. Click Run attack scenario
5. Inspect the real model's structured Agent proposal
6. Observe independent T3N TEE DENY
7. Submit a legitimate prompt or prepare the minimum safe action
8. Observe T3N ALLOW/REDACT and the logical private-data boundary
9. Record explicit human authorization only after ALLOW
10. Execute protected remediation when synthetic egress/read-back is configured
11. Observe PENDING_VERIFICATION or the verification transition
12. Accept COMPLETED only when independent read-back shows VERIFIED
13. Open Evidence and confirm T3N_TESTNET metadata/results
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
T3N / Rust WASM policy
   DENY | REDACT | ALLOW
                    |
            authenticated human
                    |
             one-time capability
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
```

Trust model:

- **Prompt is untrusted.** It may contain instruction injection and never becomes an authorization source.
- **The model is not a security boundary.** It can only call one proposal tool with a closed JSON schema.
- **Unknown or privileged model fields are rejected.** Decisions, overrides, identities, credentials, secrets, API keys and literal `{{profile...}}` markers are rejected before T3N evaluation.
- **Private data is referenced, not copied.** The model/application may request `verified_email`; only Rust/WASM can convert it to the official T3N profile marker.
- **T3N identities are server-derived.** Agent DID comes from the authenticated agent session; tenant `pii_did` from the authenticated tenant session.
- **Rust/WASM owns policy and private-reference mapping.** The model cannot manufacture `ALLOW` or select arbitrary profile namespaces.
- **Spring Boot owns durable business authorization and execution state.** It persists logical refs, the human authorization transition and the remediation state machine.
- **Gateway owns T3N sessions and privileged execution.** It requires service authentication and validates/consumes the one-time capability before execution.
- **Private KV owns remediation credentials/endpoints.** The protected credential, action URL and verification URL are not browser inputs.
- **T3N protected egress is the profile-resolution and remediation boundary.** Responses are minimized before returning to application layers.
- **HTTP acceptance is not truth.** Completion is derived from an independent closed read-back, not from the original response code.

## Security claims matrix

| Claim | Current status | Source of truth |
|---|---|---|
| Real configured model produces structured proposals | PROVED LOCAL | provider adapter + agent/backend tests |
| Tool schema cannot accept decision/override/DID/secret authority fields | PROVED LOCAL | `proposal-schema.test.ts` |
| Literal profile placeholders and unknown private refs are rejected | PROVED LOCAL | proposal schema + Spring validation + Rust policy tests |
| `verified_email` is the only current logical private reference | PROVED LOCAL | Rust policy/remediation mapping |
| `verified_email` is allowed only for `notify-security` / `incident-notification` | PROVED LOCAL | Rust policy tests |
| Rust maps `verified_email` to `{{profile.verified_contacts.email.value}}` | PROVED LOCAL | Rust remediation regression test |
| Java/H2 persists logical refs, not plaintext profile values | PROVED LOCAL | entity/service/API model + tests |
| Human capability binds private refs as well as normal fields | PROVED LOCAL | signer/verifier tests |
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

`private_refs` contains domain-level categories only. The model cannot submit `{{profile...}}`, `profile.*`, a private value or a new private namespace. Provider failure, invalid JSON, missing/multiple tool calls, extra keys or unsafe authority fields fail closed.

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
Human authorization capability signs privateRefsHash
        |
        v
Gateway verifies exact private_refs set
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

If the profile field is unavailable, user context is missing, placeholder is denied, delegation is revoked or the destination host is not authorized, execution fails closed. Error text never returns the resolved value.

## Verified remediation flow

```text
T3N TEE ALLOW
      |
Authenticated operator authorizes
      |
Spring checks persisted action + ALLOW
      |
HMAC capability binds fields + private refs
      |
Atomic pessimistic claim creates EXECUTING
      |
Gateway verifies service token + capability
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

### Remediation verification
The contract exposes separate `execute-remediation` and `verify-remediation` functions. Live delegation includes both only when required. Evidence orchestration derives the allowed HTTPS hosts from the configured remediation and verification endpoints rather than broadening the grant arbitrarily.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new tenant/agent credentials, operator credentials, provider key, service/capability keys and persistent gateway `/data`. Existing private keys are not transferred through GitHub/UI. Profile-backed live evidence must use a dedicated test profile with synthetic data.

## Evidence model

```text
WASM bytes -> SHA-256 -> deployment-manifest.json
                         |
                         +-> same DIDs / contract / version / hash
                                      |
                                      v
                               testnet-run.json
```

`PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means the scenario was not executed and is never counted as success. The profile-placeholder execution scenario remains `NOT_RUN` until a compatible profile/user context exists; local tests do not upgrade that claim to live proof.

The live remediation scenario is stricter:

```text
attack DENY
   -> execute-remediation PENDING_VERIFICATION
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

When preparing egress evidence, configure `SECURITY_API_URL` and the separate `SECURITY_VERIFICATION_URL`. Both are sealed into the private map, and the delegation host allowlist is derived from those HTTPS endpoints. Generated metadata is leak-scanned for operator credentials, T3N keys, AI provider key, service token, capability signing key, remediation key and configured sentinel.

## Screenshot shot list

1. Live T3N operational status.
2. Attack prompt + provider/model provenance + model proposal + `DENY`.
3. `REDACT` data-minimization evidence.
4. Private-reference panel showing `Verified email`, Agent plaintext `NO`, Java plaintext `NO`, T3N egress resolution boundary.
5. Legitimate proposal/minimum remediation + `ALLOW`.
6. Human authorization separate from execution.
7. Execution/verification panel showing the state machine.
8. Verified remediation screenshot only after `Verification = VERIFIED` and `Final state = COMPLETED`.
9. Evidence Center with T3N_TESTNET metadata/results and optional scenarios honestly PASS/FAIL/NOT RUN.

Never capture passwords, cookies, T3N keys, provider key, service/capability keys, remediation secret, resolved profile PII, `.env` or raw logs.

## Demo video storyboard

```text
0–15s    Problem: model compromise must not become authority or data access
15–35s   Show live tenant/agent/contract/delegation identities
35–60s   Attack prompt -> real provider -> structured Agent proposal
60–80s   Independent T3N TEE DENY
80–105s  Show logical private reference instead of private value
105–125s T3N ALLOW/REDACT and explicit human authorization
125–150s Execute -> accepted/PENDING_VERIFICATION
150–165s Independent read-back -> VERIFIED/COMPLETED when available
165–180s Evidence Center -> exact live proof status
```

## UX/claim wording rules

- **agent proposal**: model-produced structured request, not authorization;
- **logical private reference**: category such as `verified_email`, not the private value;
- **resolved by T3N at egress**: only claim for executions where T3N actually resolved the placeholder;
- **authenticated**: a session identity was authenticated;
- **resolved**: contract id/version were resolved;
- **delegated**: an active member grant was observed;
- **authorized**: human business authorization was persisted;
- **accepted / pending verification**: the execution endpoint acknowledged the operation; final state is not yet proven;
- **verified**: independent read-back matched the closed expected state;
- **completed**: Spring persisted completion only after verified read-back;
- **unverified**: outcome is ambiguous/not confirmed and no automatic re-execution occurs;
- **execution proof**: short-lived server-to-gateway capability, not hardware attestation;
- **proved live**: matching live evidence/capture exists.

Do not say “guarantees GDPR compliance”, “hardware verified”, “exactly once”, “at most once”, “profile resolution proved live” or “completed from HTTP 2xx” without corresponding evidence/contract.

This file is the repository source of truth for the public submission narrative and handover model.
