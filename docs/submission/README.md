# T3 Privacy Guard — Submission & Judge Guide

## Product position

**T3 Privacy Guard is an enterprise trust runtime for AI agents.** Its purpose is not to make the model itself trustworthy. Its purpose is to keep policy, identity, private-data resolution, business authorization and completion proof outside the model even when the model is manipulated.

The product thesis is intentionally simple:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

The current challenge implementation applies that pattern to confidential incident response. The Rust policy already recognizes four concrete operational actions: credential revocation, account isolation, incident recording and security notification. The dashboard currently emphasizes the adversarial credential-remediation flow because it exercises the strongest end-to-end controls in one scenario.

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host`, normal field names and enumerated logical private-data references. It cannot provide a policy decision, DID, override, secret, execution capability or literal T3N profile placeholder.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM policy through the authenticated Agent DID and tenant `pii_did`. A malicious exfiltration proposal receives `DENY`. A minimum legitimate proposal can receive `ALLOW`, but `ALLOW` is still not execution: an authenticated operator must explicitly authorize remediation, after which Spring emits a short-lived one-time signed capability bound to the exact action, decision, normal fields and logical private references. The gateway verifies service authentication, capability integrity, expiry, body equality and anti-replay state before protected T3N execution.

For private profile data, the application carries only a category such as `verified_email`. The Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`; the real value can be resolved only by T3N during protected egress and is not returned to React, Java, the model or gateway responses.

Protected execution is fail-safe under retries. Spring creates a persistent atomic claim before egress. The TEE sends `requestId` as the stable idempotency key, but a 2xx only produces `PENDING_VERIFICATION`. A distinct T3N `verify-remediation` read-back must observe the matching `operation_id` and the closed expected state `REVOKED` before the business state becomes `COMPLETED`. Ambiguous outcomes become `UNVERIFIED`; they may be re-verified but are never automatically executed again.

The project reports only verifiable state: `NOT_RUN` never becomes `PASS`, simulated output is not labelled live, profile-placeholder resolution is not labelled proved live until a compatible testnet profile actually executes it, external execution is not labelled completed from HTTP acceptance alone, public Agent registration is not labelled authorization, and hardware attestation is not claimed without a concrete artifact.

## Why this is more than PII detection

A normal PII filter answers questions such as “does this prompt contain an email address?”. T3 Privacy Guard addresses a larger authority problem:

```text
What may the agent propose?
        |
Who is the authenticated agent?
        |
Is that agent publicly registered/discoverable?
        |
Which action/purpose/host/data are allowed?
        |
Which private value may be resolved, and where?
        |
Has a human authorized the exact action?
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
  -> T3N Rust/WASM policy evaluates the request
  -> DENY
  -> no human authorization
  -> no protected egress
```

The important observation is not merely that a keyword was detected. The model is allowed to produce the malicious proposal, but **the model does not control the decision boundary**.

### Legitimate path

```text
Minimum legitimate proposal
  -> T3N policy ALLOW
  -> authenticated human authorizes exact action
  -> Spring signs one-time capability
  -> gateway validates body equality + expiry + anti-replay
  -> T3N protected execution
  -> external acknowledgement = PENDING_VERIFICATION
  -> separate read-back
  -> VERIFIED REVOKED
  -> Spring records COMPLETED
```

The important observation is that no single success signal is trusted to mean more than it proves.

## Current enterprise actions

The current Rust policy defines these real action contracts:

| Action | Purpose | Allowed normal fields | Private reference |
|---|---|---|---|
| `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none |
| `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none |
| `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none |
| `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `verified_email` allowed |

The challenge UI currently spotlights credential revocation because it demonstrates policy enforcement, explicit authorization, protected egress, replay resistance and independent completion verification in a single path. The other policy actions are not presented here as broader vertical products that have already been built.

## Judge quick path

```text
1. Sign in as application operator
2. Read the product thesis before inspecting low-level metadata
3. Confirm Gateway / Tenant / Agent authentication / Agent onboarding / Contract / Delegation separately
4. Verify that Agent onboarding is REGISTERED for the public submission capture, without treating registration as permission
5. Inspect the attack prompt
6. Click Run attack scenario
7. Inspect the real model's structured Agent proposal
8. Observe independent T3N TEE DENY
9. Submit a legitimate prompt or prepare the minimum safe action
10. Observe T3N ALLOW/REDACT and the logical private-data boundary
11. Record explicit human authorization only after ALLOW
12. Execute protected remediation when synthetic egress/read-back is configured
13. Observe PENDING_VERIFICATION or the verification transition
14. Accept COMPLETED only when independent read-back shows VERIFIED
15. Open Evidence and confirm exact T3N_TESTNET claims, Agent Card linkage and NOT_RUN boundaries
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
- **Public Agent Card is identity metadata, not authority.** It is built only from the authenticated Agent DID and verified through public T3N resolution. `REGISTERED` proves discoverability of that identity, not contract access, Member Delegation or TEE attestation.
- **Rust/WASM owns policy and private-reference mapping.** The model cannot manufacture `ALLOW` or select arbitrary profile namespaces.
- **Spring Boot owns durable business authorization and execution state.** It persists logical refs, the human authorization transition and the remediation state machine.
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
| Is that identity publicly registered/discoverable? | T3N public Agent Card resolver bound to the authenticated Agent DID |
| Which tenant/data owner is the authorization subject? | Authenticated tenant session |
| Is action/purpose/host/data allowed? | Rust/WASM policy |
| Is contract access granted to the agent? | Member Delegation |
| Is business remediation approved? | Authenticated human operator |
| Is this exact execution authorized now? | Signed one-time capability |
| May a private value be resolved? | Closed Rust mapping + T3N protected boundary |
| Did the side effect complete? | Independent read-back + Spring state machine |

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
| Agent Card builder uses only the authenticated canonical Agent DID and supported public metadata | PROVED LOCAL | `agent-card.test.ts` |
| Agent Card mismatch/unsupported service/network failure never becomes `REGISTERED` | PROVED LOCAL | `agent-card.test.ts` + backend/frontend tests |
| Public Agent Card is registered on T3N for the submission agent | NOT CLAIMED | only when read-only resolver + evidence bundle report `REGISTERED` |
| Agent registration grants contract authorization | NOT CLAIMED | Member Delegation remains the authority boundary |
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

### Agent Card onboarding

The self-registered public Agent Card is built from `AgentSession.getAgentDid()` only. The deterministic public payload advertises the implemented `DID` service, keeps `x402Support=false`, stays below the T3N hosted-card size limit and contains no credentials. Read-only verification validates DID equality, active state, schema and service allowlist before reporting `REGISTERED`. Registration remains separate from Member Delegation.

### Profile placeholders

The application never lets the LLM/browser choose a raw placeholder. `verified_email` is mapped inside the TEE contract to the documented `profile.verified_contacts.email.value` marker, limiting the public application contract to an auditable domain vocabulary.

### Remediation verification

The contract exposes separate `execute-remediation` and `verify-remediation` functions. Live delegation includes both only when required. Evidence orchestration derives the allowed HTTPS hosts from the configured remediation and verification endpoints rather than broadening the grant arbitrarily.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new tenant/agent credentials, operator credentials, provider key, service/capability keys and persistent gateway `/data`. Existing private keys are not transferred through GitHub/UI. Profile-backed live evidence must use a dedicated test profile with synthetic data.

## Evidence model

```text
authenticated Agent DID
        |
        v
public Agent Card resolver -> state / URI / SHA-256 / services / verifiedAt
        |
        v
WASM bytes -> SHA-256 -> deployment-manifest.json
                         |
                         +-> same DIDs / contract / version / hash
                                      |
                                      v
                               testnet-run.json
```

`PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means the scenario was not executed and is never counted as success. The profile-placeholder execution scenario remains `NOT_RUN` until a compatible profile/user context exists; local tests do not upgrade that claim to live proof. A locally generated card does not prove remote registration: only public T3N resolution that validates as `REGISTERED` does.

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

### Public Agent onboarding

```bash
cd t3n-gateway
npm install
npm run agent:card:verify   # read-only
npm run agent:card:publish  # explicit mutation; may consume credits
```

The submission should publish the Agent Card explicitly once for the intended Agent DID, then use the read-only verifier and live evidence/capture paths for proof. `evidence:live` never publishes the card automatically.

### Live T3N evidence

```bash
cd t3n-gateway
npm install
npm run evidence:live
```

When preparing egress evidence, configure `SECURITY_API_URL` and the separate `SECURITY_VERIFICATION_URL`. Both are sealed into the private map, and the delegation host allowlist is derived from those HTTPS endpoints. Generated metadata is leak-scanned for operator credentials, T3N keys, AI provider key, service token, capability signing key, remediation key and configured sentinel.

## Screenshot shot list

Screenshots must tell the same authority-separation story as the product, not merely prove that screens exist.

1. Product header + live T3N operational status showing Agent authentication, Agent onboarding `REGISTERED`, contract and delegation as separate states.
2. Attack prompt + provider/model provenance + model proposal + `DENY`.
3. `REDACT` data-minimization evidence.
4. Private-reference panel showing `Verified email`, Agent plaintext `NO`, Java plaintext `NO`, T3N egress resolution boundary.
5. Legitimate proposal/minimum remediation + `ALLOW`.
6. Human authorization separate from execution.
7. Execution/verification panel showing the state machine.
8. Verified remediation screenshot only after `Verification = VERIFIED` and `Final state = COMPLETED`.
9. Evidence Center with T3N_TESTNET metadata/results, Agent Card URI/hash/state and optional scenarios honestly PASS/FAIL/NOT RUN.

Never capture passwords, cookies, T3N keys, provider key, service/capability keys, remediation secret, resolved profile PII, `.env` or raw logs.

## Demo video storyboard

```text
0–10s    Product thesis: AI proposes; it does not own authority
10–25s   Show authenticated tenant/agent, REGISTERED onboarding, contract and ACTIVE delegation as distinct facts
25–50s   Attack prompt -> real provider -> malicious structured proposal
50–70s   Independent T3N TEE DENY; no protected egress
70–95s   Show logical private reference instead of private value
95–115s  Minimum legitimate request -> ALLOW/REDACT
115–130s Explicit human authorization
130–150s Protected execution -> accepted/PENDING_VERIFICATION
150–165s Independent read-back -> VERIFIED/COMPLETED when available
165–180s Evidence Center -> exact proof status, Agent Card linkage and NOT_RUN boundaries
```

## UX and claim wording rules

The submission must lead with user/business meaning, then expose the technical proof. Technical labels remain precise.

- **agent proposal**: model-produced structured request, not authorization;
- **logical private reference**: category such as `verified_email`, not the private value;
- **resolved by T3N at egress**: only claim for executions where T3N actually resolved the placeholder;
- **authenticated**: a session identity was authenticated and its canonical DID came from that session;
- **registered**: the public Agent Card resolved through T3N and matched the authenticated Agent DID plus supported card rules; this means discoverability, not authorization or attestation;
- **resolved**: contract id/version were resolved;
- **delegated**: an active member grant was observed and is the contract authorization source;
- **authorized**: human business authorization was persisted;
- **accepted / pending verification**: the execution endpoint acknowledged the operation; final state is not yet proven;
- **verified**: independent read-back matched the closed expected state;
- **completed**: Spring persisted completion only after verified read-back;
- **unverified**: outcome is ambiguous/not confirmed and no automatic re-execution occurs;
- **execution proof**: short-lived server-to-gateway capability, not hardware attestation;
- **proved live**: matching live evidence/capture exists.

Do not say “guarantees GDPR compliance”, “hardware verified”, “exactly once”, “at most once”, “profile resolution proved live”, “registration grants access” or “completed from HTTP 2xx” without corresponding evidence/contract.

This file is the repository source of truth for the public submission narrative and handover model.

## Persistent trust-manifest rollback boundary

Before either T3N identity is authenticated, the gateway verifies the official signed trust manifest and reads the persisted high-water mark for the selected network. If a floor exists, `fetchTrustedManifest(network, { minVersion })` is mandatory. Tenant and Agent sessions share the same `TrustManifestFloorStore`, so one runtime cannot accept separate rollback histories for the same network.

The floor is monotonic and network-scoped: accepting version 101 allows 101 or a later verified version, while version 100 is rejected even after a gateway restart. The state is written atomically to persistent `/data` storage and contains only the network, accepted version and acceptance timestamp. Missing state is valid only for first bootstrap; malformed, truncated or unreadable state fails closed and is never silently reset. Resetting the floor is an explicit operational recovery decision because it discards rollback history.

For judging and evidence, the claims are deliberately separate:

- **Trust anchor VERIFIED**: the signed T3N manifest established the cluster trust boundary used for authentication.
- **Rollback floor PERSISTED**: a valid monotonic manifest-version floor was durably stored and reused across restarts.
- **Trust manifest version**: the observed high-water version associated with that evidence bundle.
- **Agent onboarding REGISTERED**: the public Agent Card resolved and matched the authenticated Agent DID plus supported public metadata. It is discoverability evidence only.
- **Member Delegation ACTIVE**: the tenant granted the observed contract functions/scopes/hosts; this is authorization, unlike Agent registration.
- **Hardware attestation**: not implied by any of the states above and not claimed without a separate execution-specific artifact.

The Evidence Center exposes those sanitized states and the Manual da Tela explains the expected failure cases (`TRUST MANIFEST UNAVAILABLE`, `ROLLBACK REJECTED`, `TRUST FLOOR CORRUPTED`, `VERSION NOT EXPOSED BY SDK`, `NOT REGISTERED`, `CARD/DID MISMATCH`, `UNAVAILABLE`) without exposing trust-manifest contents or credentials.
