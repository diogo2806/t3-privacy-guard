# T3 Privacy Guard — Submission & Judge Guide

## Product position

**T3 Privacy Guard is an enterprise trust runtime for AI agents.** Its purpose is not to make the model itself trustworthy. Its purpose is to keep policy, identity, private-data resolution, business authorization and completion proof outside the model even when the model is manipulated.

The product thesis is intentionally simple:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

The challenge implementation applies that pattern to confidential incident response. The Rust policy recognizes four concrete operational actions: credential revocation, account isolation, incident recording and security notification. The Protection demo exposes all four as business-readable presets while preserving the strongest end-to-end execution/read-back path for credential revocation only.

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host`, normal field names and enumerated logical private-data references. It cannot provide a policy decision, DID, override, secret, execution capability or literal T3N profile placeholder.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM policy through authenticated T3N identities. The Tenant, Proposal Agent and Protected Executor have separate sessions and canonical DIDs. A malicious exfiltration proposal receives `DENY`. A minimum legitimate proposal can receive `ALLOW`, but `ALLOW` is still not execution: an authenticated operator must explicitly authorize remediation, after which Spring emits a short-lived one-time signed capability bound to the exact action, decision, normal fields, logical private references, Protected Executor DID and policy provenance.

Delegation is also split into two proofs. A **Member grant** is the Tenant-side record that names the grantee, contract, functions, scopes, hosts and validity window. It proves that a matching grant document exists, but it does not by itself prove that the authenticated principal is effectively authorized at that moment. When a matching grant is active, the gateway calls T3N `checkDelegation()` through the authenticated Proposal Agent or Protected Executor client. Only `authorised=true` produces **effective access `ACTIVE`**. `authorised=false` produces `INCOMPLETE`; transport, parsing or malformed verdicts produce `UNKNOWN`. Both non-success states fail closed.

For private profile data, the application carries only a category such as `verified_email`. The Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`; the real value can be resolved only by T3N during protected egress and is not returned to React, Java, the model or gateway responses.

Protected credential revocation is fail-safe under retries. Spring creates a persistent atomic claim before egress. The TEE sends `requestId` as the stable idempotency key, but a 2xx only produces `PENDING_VERIFICATION`. A distinct T3N `verify-remediation` read-back must observe the matching `operation_id` and the closed expected state `REVOKED` before the business state becomes `COMPLETED`. Ambiguous outcomes become `UNVERIFIED`; they may be re-verified but are never automatically executed again.

The operational policy used by contract `0.4.0` is versioned in private T3N KV. Each decision carries the exact `policyVersion` and deterministic SHA-256 `policyHash`; critical invariants remain compiled in WASM. Missing or invalid policy fails closed. Human authorization and protected execution are bound to the same version/hash so a policy change after approval cannot silently reuse stale authority.

The project reports only verifiable state: `NOT_RUN` never becomes `PASS`, simulated output is not labelled live, profile-placeholder resolution is not labelled proved live until a compatible testnet profile actually executes it, an observed Member grant is not labelled effective authority, external execution is not labelled completed from HTTP acceptance alone, and hardware attestation is not claimed without a concrete artifact.

Each live evidence bundle also records the full public Git commit SHA and whether the source tree was `CLEAN` or `DIRTY` when evidence generation began. Submission evidence fails closed on a dirty tree by default. The source revision provides reproducibility and public-code traceability; the WASM SHA-256 and policy hash remain the identities of the executed artifacts, and none of these fields is described as an independent code audit or hardware attestation.

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
Minimum legitimate credential-revocation proposal
  -> Proposal Agent session authenticated
  -> Member grant observed
  -> T3N checkDelegation -> authorised=true
  -> effective Proposal access ACTIVE
  -> T3N policy ALLOW + exact version/hash
  -> authenticated human authorizes exact action + policy provenance
  -> Protected Executor session authenticated
  -> Executor Member grant observed
  -> T3N checkDelegation -> authorised=true
  -> effective Executor access ACTIVE
  -> Spring signs one-time capability bound to Executor DID
  -> gateway validates body equality + expiry + anti-replay
  -> T3N rechecks active version/hash
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
| Credential compromised | `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none | Policy + human authorization + protected execution + independent `REVOKED` read-back |
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

Spring persists the version/hash with the policy decision. Human authorization requires versioned provenance. The one-time remediation capability signs the same version/hash, the gateway verifies body equality, and T3N protected execution re-reads the current private policy before egress. If the policy changed after authorization, execution is rejected and the action must be evaluated again.

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

PLATFORM DELEGATION AUTHORIZED
  authenticated principal called checkDelegation() and T3N returned authorised=true

EFFECTIVE ACCESS ACTIVE
  Member grant is active + platform delegation is authorized
```

The runtime never derives a canonical DID from configuration or browser input. `pii_did` for `checkDelegation()` comes only from `tenantSession.getTenantDid()`. The principal performing the check is the authenticated Proposal Agent or Protected Executor client. The contract id is the resolved canonical contract id. Functions and scopes are taken from the observed Member grant and are not widened to `*`.

Effective-state semantics:

| Member state | T3N platform verdict | Effective state | Operational? |
|---|---|---|---|
| `ACTIVE` | `authorised=true` | `ACTIVE` | eligible, subject to all other controls |
| `ACTIVE` | `authorised=false` | `INCOMPLETE` | no |
| `ACTIVE` | error/malformed/unavailable | `UNKNOWN` | no |
| `SCHEDULED` | not called | `INCOMPLETE` | no |
| `REVOKED` | not called | `INCOMPLETE` | no |
| `NOT_GRANTED` | not called | `INCOMPLETE` | no |
| `UNKNOWN` | not called | `UNKNOWN` | no |

The Proposal Agent and Protected Executor are evaluated independently. The dashboard reports the control plane ready only when both effective states are `ACTIVE` together with the required authenticated identities and resolved contract.

`satisfied` and `missing` are exposed only as bounded sanitized labels. Raw SDK objects, credentials, tokens and arbitrary response payloads are never forwarded to Spring or the browser.

## Judge quick path

```text
1. Sign in as application operator.
2. Read the product thesis before inspecting low-level metadata.
3. Confirm Tenant, Proposal Agent and Protected Executor are authenticated as separate principals.
4. Inspect Agent onboarding separately from authorization.
5. Open technical status and distinguish Member grant, Platform delegation and Effective access for Proposal Agent and Executor.
6. Treat the control plane as operational only when both Effective access states are ACTIVE.
7. Choose Credential compromised and inspect the synthetic attack prompt.
8. Click Ask agent and inspect the real model proposal.
9. Observe independent T3N TEE DENY and the exact policy version/hash.
10. Switch through Account takeover, Record security incident and Notify security contact; confirm preset selection grants no authority.
11. For Notify security contact, confirm only logical verified_email appears, never plaintext email or raw profile placeholder.
12. Return to Credential compromised and prepare the minimum revocation path.
13. Observe T3N ALLOW/REDACT and the minimum-data boundary.
14. Record explicit human authorization only after ALLOW under the displayed policy version/hash.
15. Execute protected credential revocation when synthetic egress/read-back is configured.
16. Confirm execution is bound to the authenticated Protected Executor and the same policy provenance.
17. Observe PENDING_VERIFICATION or the verification transition.
18. Accept COMPLETED only when independent read-back shows VERIFIED.
19. Open Evidence and confirm the full Source commit, Source tree CLEAN/DIRTY state, exact T3N_TESTNET claims, contract/WASM/policy provenance and NOT_RUN boundaries.
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
      |      +--> checkDelegation --------------+
      |      +--> effective access
      |
      +--> Protected Executor session
             |
             +--> Member grant
             +--> checkDelegation
             +--> effective access
      |
      v
T3N / Rust WASM policy
      | private T3N KV policy version/hash
   DENY | REDACT | ALLOW
                    |
            authenticated human
                    |
             one-time capability
       bound to policy + Executor DID
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
- **Scenario selection is presentation state.** It loads synthetic input and grants no authority.
- **The model is not a security boundary.** It can only call one proposal tool with a closed JSON schema.
- **Unknown or privileged model fields are rejected.** Decisions, overrides, identities, credentials, secrets, API keys and literal `{{profile...}}` markers are rejected before T3N evaluation.
- **Private data is referenced, not copied.** The model/application may request `verified_email`; only Rust/WASM can convert it to the official T3N profile marker.
- **T3N identities are server-derived.** Tenant, Proposal Agent and Protected Executor DIDs come from authenticated sessions.
- **A Member grant is necessary but not sufficient.** Runtime readiness uses the authenticated principal-side T3N `checkDelegation()` verdict.
- **Delegation checks fail closed.** `authorised=false`, malformed verdicts or platform errors cannot become ready states.
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
| Which Tenant identity is the authorization subject? | Authenticated Tenant session |
| Which principal proposes policy evaluation? | Authenticated Proposal Agent session |
| Which principal executes protected remediation? | Authenticated Protected Executor session |
| Does a matching grant record exist? | Tenant-side Member Delegation document |
| Is that principal effectively delegated now? | Principal-side T3N `checkDelegation()` with Tenant DID + canonical contract + observed functions/scopes |
| Which operational rules are active? | Versioned private T3N KV policy |
| Which critical rules cannot be relaxed? | Rust/WASM invariants |
| Is action/purpose/host/data allowed? | Rust/WASM evaluation of active policy |
| Is business remediation approved? | Authenticated human operator bound to policy provenance |
| Is this exact execution authorized now? | Signed one-time capability bound to Protected Executor DID |
| May a private value be resolved? | Closed Rust mapping + T3N protected boundary |
| Did the side effect complete? | Independent read-back + Spring state machine |

## Security claims matrix

| Claim | Current status | Source of truth |
|---|---|---|
| Real configured model produces structured proposals | PROVED LOCAL | provider adapter + agent/backend tests |
| Tool schema cannot accept decision/override/DID/secret authority fields | PROVED LOCAL | `proposal-schema.test.ts` |
| Four enterprise presets map to existing policy actions without authorizing them | PROVED LOCAL | `scenarioDefinitions.ts` + `EnterpriseScenarioCatalog.test.tsx` |
| Scenario selection does not submit the prompt automatically | PROVED LOCAL | `EnterpriseScenarioCatalog.test.tsx` + controlled prompt flow |
| Tenant DID derives from authenticated T3N session | PROVED LOCAL | gateway session code/tests |
| Proposal Agent and Protected Executor use separate authenticated credentials/DIDs | PROVED LOCAL | session separation + status tests |
| Member-grant validity windows fail closed | PROVED LOCAL | `delegation-service.test.ts` |
| Effective access requires authenticated principal-side `checkDelegation()` | PROVED LOCAL | `delegation-service.test.ts` |
| `pii_did` for the delegation check is the authenticated Tenant DID | PROVED LOCAL | `delegation-service.test.ts` |
| `authorised=false` cannot become operational readiness | PROVED LOCAL | gateway/backend/frontend tests |
| `checkDelegation()` error or malformed response becomes `UNKNOWN`, never ready | PROVED LOCAL | gateway/backend/frontend tests |
| UI separates Member grant, Platform delegation and Effective access | PROVED LOCAL | `SystemStatusBar.test.tsx`, `TrustFlowSummary.test.tsx` |
| Canonical policy hashing is deterministic | PROVED LOCAL | `policy-document.test.ts` |
| Reusing a version with different content is rejected | PROVED LOCAL | policy provisioner + tests |
| Missing/invalid policy fails closed | PROVED LOCAL | Rust policy tests + gateway contract path |
| Critical forbidden-secret/private-ref invariants cannot be relaxed by KV policy | PROVED LOCAL | Rust adversarial/policy tests |
| Policy version/hash propagate through decision, persistence, UI and evidence metadata | PROVED LOCAL | backend/frontend/evidence tests |
| Live evidence source revision is a full Git SHA with explicit CLEAN/DIRTY state | PROVED LOCAL | `source-revision.test.ts`, manifest/backend/frontend evidence tests |
| Remediation capability binds exact policy version/hash | PROVED LOCAL | signer/verifier + remediation tests |
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

If the profile field is unavailable, user context is missing, placeholder is denied, delegation is not effectively authorized, the destination host is not authorized or policy provenance no longer matches, execution fails closed. Error text never returns the resolved value.

## Verified remediation flow

```text
T3N TEE ALLOW for revoke-credential
      | exact policy version/hash
Authenticated operator authorizes
      | same policy provenance + Executor DID
Spring checks persisted action + ALLOW
      |
HMAC capability binds fields + private refs + policy provenance + Executor DID
      |
Atomic pessimistic claim creates EXECUTING
      |
Gateway verifies service token + capability
      |
Protected Executor effective access must be ACTIVE
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
- verification outage or contradictory state becomes `UNVERIFIED`;
- `UNVERIFIED` with an operation id can invoke **Verify external state**, which performs read-back only;
- a reload fetches persisted remediation state through a read-only endpoint and does not execute/verify anything.

`requestId` is a stable logical idempotency key. The application prevents duplicate local initiation through its durable claim. It does **not** claim exactly-once or provider-level at-most-once unless the external provider explicitly honors the idempotency key.

## Terminal 3 integration findings

### Member Delegation and effective authorization

Member Delegation is treated as the Tenant-side grant document. Non-empty functions/scopes are required. A matching `ACTIVE` record is not promoted directly to operational authority. The gateway uses the authenticated grantee client to call `checkDelegation()` with the resolved contract, authenticated Tenant DID and exact observed functions/scopes. Proposal Agent and Protected Executor are checked independently.

### Delegated `pii_did`

Every effective-delegation check and delegated execution derives `pii_did` internally from `tenantSession.getTenantDid()`. Browser, Java and LLM cannot supply or override the authorization subject.

### Profile placeholders

The application never lets the LLM/browser choose a raw placeholder. `verified_email` is mapped inside the TEE contract to the documented `profile.verified_contacts.email.value` marker, limiting the public application contract to an auditable domain vocabulary.

### Versioned private policy

Operational rules are provisioned to private T3N KV under immutable version snapshots and selected through the `current` pointer. The canonical policy SHA-256 is carried as provenance across evaluation, authorization, evidence and protected execution. Policy rollback is explicit; a hash is not described as attestation.

### Remediation verification

The contract exposes separate `execute-remediation` and `verify-remediation` functions. Executor Member Delegation includes both only when required. Evidence orchestration derives the allowed HTTPS hosts from the configured remediation and verification endpoints rather than broadening the grant arbitrarily.

## Public Agent onboarding and independent Activity provenance

Public registration and authorization are intentionally not conflated:

```text
Proposal Agent AUTHENTICATED
      |
      +--> Agent Card -> REGISTERED / NOT_REGISTERED / MISMATCH / UNAVAILABLE
      |
      +--> Member grant -> ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
                          |
                          +--> checkDelegation -> Authorized / Not authorized / Unavailable
                                               |
                                               +--> Effective access ACTIVE / INCOMPLETE / UNKNOWN
```

The generated Agent Card is derived from the DID returned by the authenticated Proposal Agent session, not from a configured/hardcoded DID. It advertises only the supported `DID` service for that same identity, is bounded to the hosted-card size limit and rejects sensitive metadata/private-key-shaped values. The implementation does not advertise unsupported A2A/MCP services or x402 payment capability.

Operational commands:

```bash
cd t3n-gateway
npm run agent:card:verify    # read-only registry verification
npm run agent:card:publish   # explicit mutable host-card operation; may consume credits
```

The Evidence Center/status surface can show the observed onboarding state. The deployment manifest may contain the public card URI, SHA-256 of the exact resolved card, verification timestamp and service names. Those fields are public discoverability provenance; the hash is not a permission or attestation claim.

Local business audit and T3N Activity Log are independent evidence sources. `MATCHED` requires exact T3N sequence/hash/function provenance; `LOCAL_ONLY`, `T3N_ONLY` and `UNMATCHED` preserve the distinction when exact reconciliation is absent. An unavailable or truncated Activity Log is never converted into fabricated network proof.

## Persistent trust-manifest rollback boundary

Before Tenant, Proposal Agent or Protected Executor identity is authenticated, the gateway verifies the official signed trust manifest and reads the persisted high-water mark for the selected network. If a floor exists, `fetchTrustedManifest(network, { minVersion })` is mandatory. All three sessions share the same `TrustManifestFloorStore`, so one runtime cannot accept separate rollback histories for the same network.

The floor is monotonic and network-scoped. It is written atomically to persistent `/data` storage and contains only the network, accepted version and acceptance timestamp. Missing state is valid only for first bootstrap; malformed, truncated or unreadable state fails closed and is never silently reset.

For judging and evidence, the claims are separate:

- **Trust anchor VERIFIED**: signed T3N manifest established the cluster trust boundary used for authentication.
- **Rollback floor PERSISTED**: a valid monotonic manifest-version floor was durably stored and reused across restarts.
- **Trust manifest version**: observed high-water version associated with the evidence bundle.
- **Policy version/hash**: exact canonical operational policy provenance; not a hardware-attestation statement.
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
      +--> Member grants + checkDelegation effective access
      v
WASM bytes -> SHA-256 ----+
policy doc -> SHA-256 ----+--> deployment-manifest.json
                           |      same source revision / DIDs / contract / version / hashes
                           v
                    testnet-run.json
```

The live orchestrator captures the source revision before it writes generated evidence files. A dirty working tree is rejected by default; the explicit non-submission override records `sourceTreeClean=false` rather than hiding the state. The manifest and testnet run must contain the same source SHA/tree state or the evidence API rejects the bundle. `PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means the scenario was not executed and is never counted as success. The profile-placeholder execution scenario remains `NOT_RUN` until a compatible profile/user context exists; local tests do not upgrade that claim to live proof.

The live remediation scenario is stricter:

```text
attack DENY + policy provenance
   -> execute-remediation with same policy provenance
   -> PENDING_VERIFICATION
   -> operation_id present
   -> verify-remediation VERIFIED
   -> observed_state REVOKED
```

Anything less is not a successful completion proof.

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

When preparing egress evidence, configure `SECURITY_API_URL` and the separate `SECURITY_VERIFICATION_URL`. Both are sealed into the private map, and the delegation host allowlist is derived from those HTTPS endpoints. Generated metadata is leak-scanned for operator credentials, T3N keys, AI provider key, service token, capability signing key, remediation key and configured sentinel.

## Screenshot shot list

1. Product header + live T3N operational status.
2. Expanded technical status showing separate Tenant, Proposal Agent and Protected Executor DIDs.
3. Separate Proposal/Executor **Member grant**, **Platform delegation** and **Effective access** states; capture `Operational` only when both effective states are `ACTIVE`.
4. Four enterprise scenario cards with Credential compromised selected and the statement that presets are not permissions.
5. Attack prompt + provider/model provenance + model proposal + `DENY` + policy version/hash.
6. `REDACT` data-minimization evidence.
7. Notify security contact selected, showing logical `verified_email` and no plaintext address/raw placeholder.
8. Legitimate credential-revocation proposal/minimum remediation + `ALLOW` + policy provenance.
9. Human authorization separate from execution and bound to the same version/hash and Protected Executor.
10. Execution/verification panel showing the state machine.
11. Verified remediation screenshot only after `Verification = VERIFIED` and `Final state = COMPLETED`.
12. Evidence Center with full Source commit, Source tree state, T3N_TESTNET metadata/results, contract/WASM/policy provenance and optional scenarios honestly PASS/FAIL/NOT_RUN.

Never capture passwords, cookies, T3N keys, provider key, service/capability keys, remediation secret, resolved profile PII, `.env` or raw logs.

## Demo video storyboard

```text
0–10s    Product thesis: AI proposes; it does not own authority
10–25s   Show three authenticated T3N identities
25–40s   Show Agent Card vs Member grant vs Platform delegation vs Effective access
40–65s   Credential attack prompt -> real provider -> malicious structured proposal
65–85s   Independent T3N TEE DENY + policy provenance; no protected egress
85–105s  Switch scenarios; show isolation, record incident and logical verified_email context
105–125s Minimum credential-revocation request -> ALLOW/REDACT + policy version/hash
125–140s Explicit human authorization bound to policy provenance + Protected Executor DID
140–160s Protected execution -> active policy recheck -> PENDING_VERIFICATION
160–175s Independent read-back -> VERIFIED/COMPLETED when available
175–180s Evidence Center -> source revision + exact proof status + NOT_RUN boundaries
```

## UX and claim wording rules

The submission must lead with user/business meaning, then expose the technical proof. Technical labels remain precise.

- **enterprise scenario**: synthetic demonstration context and prompt preset, never a permission or policy decision;
- **agent proposal**: model-produced structured request, not authorization;
- **authenticated**: a T3N session proved a principal identity and yielded its canonical DID;
- **registered**: the public Proposal Agent Card resolved and matched the authenticated DID; not authorization;
- **Member grant**: Tenant-side grant record with grantee, contract, functions, scopes, hosts and validity window;
- **Platform delegation**: principal-side `checkDelegation()` verdict from T3N;
- **effective access**: runtime result; `ACTIVE` only when Member grant is active and T3N returns `authorised=true`;
- **authorized** in the platform-delegation status: only `checkDelegation().authorised=true`;
- **human authorized**: business authorization persisted for the exact action, policy provenance and Protected Executor DID;
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
- **execution proof**: short-lived server-to-gateway capability, not hardware attestation;
- **proved live**: matching live evidence/capture exists.

Do not say “Verified source” solely because a Git SHA/tree state is present, “Member grant ACTIVE = authorized”, “registered = authorized”, “Agent Card = attestation”, “guarantees GDPR compliance”, “hardware verified”, “exactly once”, “at most once”, “profile resolution proved live”, “all four scenarios execute end-to-end” or “completed from HTTP 2xx” without corresponding evidence/contract.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new Tenant, Proposal Agent and Protected Executor credentials, operator credentials, provider key, service/capability keys and persistent gateway `/data`. Existing private keys are not transferred through GitHub/UI. Profile-backed live evidence must use a dedicated test profile with synthetic data.

This file is the repository source of truth for the public submission narrative and handover model.