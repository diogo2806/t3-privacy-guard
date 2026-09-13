# T3 Privacy Guard

**Enterprise trust runtime for AI agents on the Terminal 3 Network.**

T3 Privacy Guard is built around one enterprise assumption: **the AI model can be useful and still be untrusted**. The model may interpret an incident and propose an action, but it is not allowed to decide policy, provide trusted execution values, select trusted identities, read private profile values directly, authorize a privileged side effect, or declare that side effect complete.

The system separates those authorities:

```text
Untrusted AI
    |
    | proposes action + field names only
    v
Proposal Agent DID + effective T3N delegation
    |
    v
T3N Rust/WASM policy
    |
    | DENY / REDACT / ALLOW
    v
Authenticated human authorization
    |
    | persisted principal + timestamp
    v
Ed25519 one-time execution proof
    |
    +---------------------------+
    |                           |
Gateway fail-fast          T3N/WASM verification
    |                           |
    +----------+----------------+
               |
Protected Executor DID + effective T3N delegation
               |
               v
Protected egress
               |
               v
Independent external read-back
               |
               v
VERIFIED -> COMPLETED
```

The product thesis is:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

Detailed material:

- [Submission / judge guide](docs/submission/README.md)
- [Evidence reproduction](docs/evidence/README.md)
- [Adversarial scenario matrix](docs/evidence/scenario-matrix.md)

## What the current implementation proves

A configured tool-calling model receives a textual prompt and produces a constrained structured proposal. It can choose an action, resource, purpose, destination hostname, normal field names and supported logical private references. It cannot provide a decision, T3N DID, trusted `normal_payload`, capability, approval, provider secret or raw T3N profile placeholder.

The proposal is persisted and evaluated independently by the T3N Rust/WASM policy. An unsafe proposal such as a secret field or attacker-controlled destination can become `DENY`. A legitimate proposal may become `ALLOW`, or `REDACT` when an unnecessary non-secret field must be removed.

When an action is eligible for protected remediation, the application requires a durable authenticated human approval. The browser cannot submit `authorizedBy`. Spring derives the principal from the authenticated `SecurityContext`, persists the canonical principal plus the first valid authorization timestamp, and records that provenance in the local tamper-evident audit chain. A retry by the same principal preserves the original provenance; a different principal cannot silently overwrite it.

Immediately before protected execution, Spring creates a short-lived Ed25519-signed v2 proof. The private signing key stays in the backend. The gateway and T3N contract receive only public verification material. The proof binds the exact action, decision, request, policy provenance, approved hostname, requested fields, trusted normal-payload hash, private-reference set, Protected Executor DID, SHA-256 of the authenticated application principal, persisted authorization timestamp, key version, issue/expiry times and one-time nonce.

The gateway verifies that proof as an early failure boundary. **It is not the final authority.** The same proof is passed to `execute-remediation`, where Rust/WASM verifies it again before reading protected egress credentials or performing HTTP. A valid Protected Executor credential without a valid proof is insufficient for the side effect.

## Business outcome without invented metrics

The dashboard presents a judge-first **Business Outcome** view using the same observed state as the technical flow. It does not invent future state or financial impact.

The only time metrics are derived from persisted timestamps:

```text
Time to policy decision = decision.evaluatedAt - action.createdAt

Time to verified outcome = remediation.completedAt - action.createdAt
                           only when state == COMPLETED
                           and completedAt exists
```

The UI does not calculate money saved, breach cost avoided, ROI, SLA compliance or a risk-reduction percentage because the runtime does not measure those quantities.

State wording is intentionally strict:

- `DENY`: the observed proposal was blocked before protected egress.
- `REDACT`: a smaller field/private-reference set is required.
- `ALLOW`: policy permits the next step; it is not human authorization or execution.
- `REMEDIATION_AUTHORIZED`: human approval exists, but execution has not necessarily happened.
- `PENDING_VERIFICATION`: external side effect was accepted, not proven complete.
- `UNVERIFIED`: outcome remains ambiguous or read-back did not prove the expected state.
- `COMPLETED`: independent read-back observed the closed expected external state.

## Real AI recovery after DENY

A DENY does not trigger a synthetic safe fallback. For the compromised-credential flow, the operator may ask the same configured provider for a new minimum proposal inside the same incident:

```text
first model proposal -> T3N DENY
        |
        v
operator requests a minimum follow-up proposal
        |
        v
same configured provider is called again
        |
        v
new Action Proposal is persisted
        |
        v
new proposal is independently evaluated by T3N
```

If the provider fails, no replacement action or policy decision is fabricated.

## Trusted normal-payload minimization

The model selects **field names**, not trusted execution values. Spring materializes the current synthetic demonstration values from a closed server-owned table and persists them independently from model output. `normal_payload` and `normalPayload` are rejected on the model/A2A proposal surface.

Before execution, the one-time proof binds the persisted map through `normalPayloadHash`. Java and TypeScript use the same deterministic UTF-8 representation with ASCII-lexically sorted keys:

```text
<keyByteLength>:<key>=<valueByteLength>:<value>\n
```

Rust validates the trusted map again and builds the external body only from the exact intersection:

```text
persisted trusted values ∩ policy allowed_fields
```

For credential revocation, `incident_id`, `credential_id` and `reason` must remain present. A requested extra field such as `employee_department` may be REDACTed, but its value is not serialized into protected egress.

Changing a trusted key/value after approval invalidates the proof/body binding.

## Exact approved destination binding

Policy allowlisting and human destination approval are separate checks.

The model may propose a hostname. Policy decides whether that hostname is allowed. When the operator authorizes remediation, the exact canonical hostname is included in the signed proof. The full private action URL stays in private T3N KV.

Inside `execute-remediation`, Rust resolves the configured URL, extracts its hostname and requires exact equality with the approved hostname before protected HTTP. Approval for host A cannot be reused after private configuration changes to host B, even if B is also policy-allowed.

## Human authorization provenance

`Humans authorize` is durable provenance, not a client-provided boolean.

```text
Authenticated Spring operator
        |
        v
authorize-remediation
        |
        +--> persist remediationAuthorizedBy
        +--> persist remediationAuthorizedAt
        +--> append REMEDIATION_AUTHORIZED audit event
        |
        v
execution proof contains
  operatorPrincipalHash = SHA-256(canonical principal)
  authorizedAt          = persisted approval timestamp
```

The application principal is not represented as a civil identity and is not a T3N DID. Username/e-mail and the operator hash are not published in Agent Card, public evidence or T3N Activity Log.

Legacy actions whose status says `REMEDIATION_AUTHORIZED` but have no persisted principal/timestamp are shown as `REAUTHORIZATION REQUIRED`. The system does not infer a historical approver.

## WASM-enforced one-time human authorization proof

Protected execution uses an Ed25519 proof with explicit version `v2`.

The signed claim set contains:

```text
keyId
incidentId
 actionId
 requestId
 decisionId
 action / resource / purpose
 approvedHost
 fieldsHash
 normalPayloadHash
 privateRefsHash
 policyVersion / policyHash
 executorDid
 operatorPrincipalHash
 authorizedAt
 issuedAt / expiresAt
 nonce
```

Execution path:

```text
Spring backend
  Ed25519 private PKCS#8 key
        |
        | signs v2 proof
        v
Gateway
  configured Ed25519 public SPKI
  exact body/provenance check
  local nonce-hash replay cache
        |
        | forwards the same proof
        v
T3N execute-remediation
        |
        v
Rust/WASM
  parse bounded v2 proof
  validate keyId
  load remediation_auth_public_key_spki:<keyId>
      from private contract-only KV
  verify Ed25519 signature
  verify TTL / issue time
  verify action/request/policy/destination/payload/executor bindings
  verify signed human provenance fields
  consume SHA-256(nonce) in private T3N KV replay map
        |
        v
only then continue to policy/secrets/HTTP
```

The gateway replay store is defense in depth. The contract has its own replay state so a direct SDK call that bypasses the gateway still encounters the proof requirement.

The T3N KV stores only public verification keys and nonce hashes/expiry metadata. It never receives the backend private signing key or the raw proof as replay state.

### Key rotation

`REMEDIATION_AUTH_KEY_ID` is embedded in the signed payload. `contract:setup-remediation` provisions the matching public key as:

```text
remediation_auth_public_key_spki:<keyId>
```

Rotation uses a new key pair and a new key ID. Old versioned public entries may remain only for a deliberate bounded overlap while already-issued short-lived proofs expire. The active gateway configuration accepts only its configured key ID; there is no silent v1/HMAC downgrade.

### Threat-model scope

This proof closes the direct-execution gap where possession of the Protected Executor credential alone could otherwise be enough to call `execute-remediation`.

It does **not** claim:

- civil or biometric verification of the human;
- that T3N/WASM verified the Spring login directly;
- immunity after compromise of the backend Ed25519 private signing key;
- generic hardware attestation for each request;
- exactly-once behavior at an external provider.

The contract verifies a backend-issued cryptographic proof whose human provenance was captured by the authenticated application boundary.

## Protected Executor and T3N delegation

Tenant, Proposal Agent and Protected Executor use separate T3N credentials and canonical DIDs from their authenticated sessions.

An observed Member grant is not treated as effective authorization. The Proposal Agent and Protected Executor each perform principal-side `checkDelegation()` for the exact tenant DID, contract, functions and minimum scopes.

```text
Proposal Agent
  Member grant ACTIVE
  + checkDelegation(evaluate-action) = authorised

Protected Executor
  Member grant ACTIVE
  + checkDelegation(execute-remediation, verify-remediation) = authorised
```

`authorised=false`, platform errors and unexpected results fail closed. The tenant session is not used as a substitute for the delegated principal's own effective check.

The Proposal Agent has no protected-execution grant.

## Public Agent Card and A2A boundary

Public Agent Card registration is discoverability metadata, not permission. `REGISTERED` means a public card resolved and matched the authenticated Proposal Agent DID. It does not imply Member delegation, effective access, policy authorization, human authorization or execution.

When `A2A_PUBLIC_URL` is configured as a public HTTPS `/a2a` endpoint, the card can advertise A2A. The A2A surface exposes proposal/policy evaluation only. It does not expose human authorization, trusted execution values, one-time proofs, remediation endpoints or the Protected Executor credential.

## Current policy vocabulary

| Action | Purpose | Minimum normal fields | Private reference | Full protected execution today |
|---|---|---|---|---|
| `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none | yes |
| `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none | no |
| `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none | no |
| `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `verified_email` allowed | policy/private-ref path only until notification executor is implemented |

The dashboard only exposes a protected-execution control for an action that has a real executor and independent completion verifier.

## Private profile-data boundary

The current logical private reference is deliberately narrow:

```text
verified_email
   -> closed Rust mapping
   -> {{profile.verified_contacts.email.value}}
```

The application/model carries the logical reference, not the plaintext value. React, Spring and normal gateway request/response objects do not receive a resolved e-mail. The literal profile marker is created inside Rust from a closed mapping.

This structural boundary does not mean the current project already proves live `notify-security` delivery. Profile-placeholder live evidence remains `NOT_RUN` until a compatible T3N testnet user/profile context actually executes the protected notification flow.

## Distributed remediation state machine

For the currently complete credential-revocation executor:

```text
REMEDIATION_AUTHORIZED
        |
        | durable execution claim
        v
EXECUTING
        |
        | gateway proof fail-fast
        | T3N/WASM proof + replay enforcement
        | destination equality
        | current policy re-check
        | minimized trusted payload
        v
PENDING_VERIFICATION
        |
        | independent verify-remediation read-back
        +-------------------------+
        |                         |
        v                         v
COMPLETED                    UNVERIFIED
```

Rules:

- only one application execution claim is created for an action;
- stable `requestId` is propagated as idempotency metadata;
- an HTTP 2xx is acceptance only;
- `COMPLETED` requires independent read-back of the expected `REVOKED` state;
- ambiguous outcomes are not automatically re-executed;
- the project does not claim provider-level exactly-once unless the provider independently guarantees it.

## Tamper-evident local audit

Spring stores sanitized audit events in an HMAC-SHA-256 chain per incident. The chain authenticates event ordering/content and the retained head when the verifier runs.

`AUDIT_INTEGRITY_KEY` is a backend-only secret and must be distinct from T3N credentials, the gateway service token, operator credentials and `REMEDIATION_AUTH_PRIVATE_KEY_PKCS8`.

States are intentionally precise:

- `VERIFIED`: retained local chain and authenticated head verify.
- `BROKEN`: content/link/sequence/head mismatch.
- `KEY_MISMATCH`: required configured audit key version is unavailable or does not verify.
- `LEGACY_UNVERIFIED`: rows predate the HMAC trust root and are not retroactively authenticated.

This is **tamper-evident**, not immutable or tamper-proof. An attacker who compromises both database and audit key, or the backend process capable of producing valid new MACs, is outside this local-control claim.

Local audit integrity and T3N Activity Log provenance are separate signals.

## Security boundaries

- Operator login is an application identity, not a T3N identity.
- Tenant, Proposal Agent and Protected Executor credentials are separate.
- `GATEWAY_SERVICE_TOKEN` is an independent service-to-service credential.
- `REMEDIATION_AUTH_PRIVATE_KEY_PKCS8` exists only in the backend authorization signer.
- `REMEDIATION_AUTH_PUBLIC_KEY_SPKI` is public verification material for gateway/T3N setup.
- `REMEDIATION_AUTH_KEY_ID` versions the signing/verification material.
- Protected Executor credential alone is not sufficient for `execute-remediation`; the WASM requires a valid v2 proof.
- Gateway verification is fail-fast, not the sole proof boundary.
- Gateway replay persistence at `REMEDIATION_REPLAY_STORE_PATH` is defense in depth; T3N contract replay state is a second boundary for direct calls.
- The one-time proof contains hashes/provenance, not the private signing key or operator username.
- The model cannot provide trusted `normal_payload`, identities, policy decisions or authorization proof.
- Full private action URLs and credentials remain in protected configuration/KV; only the canonical approved hostname is signed.
- Private profile values stay behind the logical-reference/placeholder boundary.
- Public Agent Card metadata is not authorization.
- Member grant state is not sufficient effective authorization without the principal-side T3N check.
- HTTP acceptance is not completion.

## Runtime configuration

Relevant variable names:

```text
T3N_API_KEY
T3N_AGENT_API_KEY
T3N_EXECUTOR_API_KEY
T3N_NETWORK
T3N_CONTRACT_TAIL
T3N_CONTRACT_VERSION
T3N_CONTRACT_NUMERIC_ID
T3N_POLICY_FILE
T3N_TRUST_FLOOR_STORE_PATH
A2A_PUBLIC_URL
GATEWAY_SERVICE_TOKEN
REMEDIATION_AUTH_PRIVATE_KEY_PKCS8
REMEDIATION_AUTH_PUBLIC_KEY_SPKI
REMEDIATION_AUTH_KEY_ID
REMEDIATION_CAPABILITY_TTL_SECONDS
REMEDIATION_REPLAY_STORE_PATH
AUDIT_INTEGRITY_KEY
AUDIT_INTEGRITY_KEY_ID
AUDIT_INTEGRITY_PREVIOUS_KEYS
AUDIT_INTEGRITY_ALLOW_LEGACY_BOOTSTRAP
OPERATOR_USERNAME
OPERATOR_PASSWORD
OPERATOR_SESSION_TIMEOUT
SESSION_COOKIE_SECURE
AI_PROVIDER
AI_API_URL
AI_API_KEY
AI_MODEL
SECURITY_API_KEY
SECURITY_API_URL
SECURITY_VERIFICATION_URL
EVIDENCE_RUN_DESTINATION_BINDING
EVIDENCE_DESTINATION_B_URL
EVIDENCE_RUN_PAYLOAD_MINIMIZATION
```

Use [.env.example](.env.example) only as a variable-name/template reference. Never commit real credentials.

`contract:setup-remediation` provisions only the remediation service values and versioned **public** Ed25519 verification key into contract-restricted T3N KV. The backend private signing key is not provisioned to the gateway or contract.

## Contract exports

The Rust contract exports:

```text
evaluate-action
execute-remediation
verify-remediation
```

`evaluate-action` returns policy decision plus exact policy version/hash.

`execute-remediation` requires the current approved policy provenance, exact destination and trusted payload, **plus a valid v2 Ed25519 authorization proof checked inside the WASM**. Proof failure occurs before reading the protected egress URL/key and before HTTP.

`verify-remediation` performs an independent external read-back for the supported closed completion state.

## Evidence rules

The repository distinguishes local regression evidence from live T3N evidence. Unit tests, mocks and unexecuted scripts are never described as live proof.

Local regression suite:

```bash
bash scripts/run-local-evidence.sh
```

T3N adversarial/evidence commands from `t3n-gateway/` include:

```bash
npm run evidence:testnet
npm run evidence:human-proof
npm run evidence:live
```

`LIVE-EXECUTOR-REQUIRES-HUMAN-PROOF` is specifically designed to authenticate the Protected Executor, confirm its delegation, then call `execute-remediation` directly **without** the human proof. PASS requires rejection by the T3N/WASM boundary. The scenario writes only sanitized status, Executor identity/delegation state and the public-key fingerprint.

The scenario is code until it is actually run against T3N testnet. An unexecuted scenario is `NOT_RUN`, never PASS. No fixture or local test is promoted into live evidence.

Other evidence boundaries remain unchanged:

- source commit/tree identity improves reproducibility but is not independent audit;
- public key fingerprint is safe evidence; private signing material is not;
- `LIVE-NORMAL-PAYLOAD-MINIMIZATION` requires controlled boolean read-back and remains `NOT_RUN` until executed;
- profile-placeholder resolution remains `NOT_RUN` until a compatible testnet user/profile context actually executes it;
- a 2xx external response is never enough for a completion claim;
- local HMAC audit integrity is not T3N execution proof or hardware attestation.

## Local builds

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm test && npm run typecheck && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

The main pinned runtime assumptions are Java 21, Node 22, TypeScript 5.9, React 19, T3N SDK 5.2.0 and Rust/WASI component target `wasm32-wasip2`.

## Deployment model

Frontend, backend and T3N gateway each have their own Dockerfile and are deployed as independent containers. There is intentionally no repository `docker-compose.yml` requirement for the target VPS/EasyPanel architecture.

Persistent application/gateway state such as H2 data, audit state, trust-manifest floor and gateway replay cache must be mounted according to deployment configuration. Contract-side verification keys and replay state live in contract-restricted T3N KV.

Future handover provisions new credentials rather than transferring existing private keys.
