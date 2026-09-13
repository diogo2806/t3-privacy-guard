# T3 Privacy Guard

**Enterprise trust runtime for AI agents on the Terminal 3 Network.**

T3 Privacy Guard is designed for a simple enterprise assumption: **the AI model can be useful and still be untrusted**. The model may analyze an incident and propose an action, but it is not allowed to become the authority that decides policy, selects trusted identities, grants itself T3N permissions, retrieves private profile values directly or declares a critical side effect completed.

The product separates those responsibilities across independent controls:

```text
Untrusted AI
    |
    | proposes
    v
Proposal Agent T3N identity
    |
    | exact effective-delegation check
    v
T3N policy / Rust WASM
    |
    | DENY / REDACT / ALLOW
    v
Human authorization
    |
    | approves exact action + policy + Executor DID
    v
One-time execution capability
    |
    v
Protected Executor T3N identity
    |
    | separate exact effective-delegation check
    v
T3N protected execution
    |
    v
Independent external read-back
    |
    v
VERIFIED -> COMPLETED
```

The central product thesis is:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

> **Judge / submission guide:** [`docs/submission/README.md`](docs/submission/README.md)  
> **Evidence reproduction:** [`docs/evidence/README.md`](docs/evidence/README.md)  
> **Adversarial matrix:** [`docs/evidence/scenario-matrix.md`](docs/evidence/scenario-matrix.md)

## What problem it solves

Enterprise agents are often given enough context and credentials to be useful. That creates a dangerous coupling: a prompt injection, compromised model or bad instruction can become data access or a real side effect if the same component is also trusted to authorize what it proposes.

T3 Privacy Guard breaks that coupling. The AI receives a deliberately narrow proposal surface. Security-sensitive authority is derived elsewhere and cannot be supplied by the model.

For private profile data, the application carries logical references such as `verified_email`, not the private value. The Rust/WASM contract maps a closed reference to the supported T3N profile marker only inside the protected execution boundary. React, Spring Boot, the model and normal gateway responses do not receive the resolved plaintext.

For side effects, an HTTP success response is not treated as business completion. The application records `COMPLETED` only after a separate read-back observes the expected closed external state.

For T3N authorization, the existence of a Member Delegation grant is also not treated as operational readiness. The authenticated principal must independently obtain an effective `checkDelegation()` verdict for the exact contract, Tenant DID, functions and scopes it is about to use.

## Where it applies

The current implementation is demonstrated through security incident response, but the trust pattern is broader. The same architecture is relevant anywhere an AI agent can recommend or trigger actions involving sensitive data or privileged operations, for example:

- security operations, where an agent can propose credential revocation, account isolation, incident recording or a security notification;
- HR or identity workflows, where an agent may need a verified attribute but should not receive the underlying private value;
- financial or compliance workflows, where policy and human authorization must remain independent from the model;
- support and operations agents, where outbound destinations and fields must be restricted to an explicit minimum;
- autonomous enterprise agents, where a useful model must not implicitly become the source of authorization.

The project does **not** claim that all of those vertical workflows are already implemented. They illustrate where the trust-runtime pattern can be applied.

## 60-second mental model

### Compromised-agent path

```text
Prompt injection
   |
   v
AI proposes:
- send api_key
- attacker.example
   |
   v
Proposal Agent effective T3N access must already be CONFIRMED
   |
   v
T3N Rust/WASM policy
   |
   v
DENY

No human authorization.
No Protected Executor invocation.
No protected egress.
No model-controlled override.
```

### Legitimate-remediation path

```text
AI proposes minimum valid action
   |
   v
Proposal Agent checkDelegation -> authorised=true
   |
   v
T3N policy -> ALLOW + policy version/hash
   |
   v
Authenticated human authorizes exact action
   |
   v
Short-lived one-time capability bound to Protected Executor DID
   |
   v
Protected Executor checkDelegation -> authorised=true
   |
   v
Protected T3N execution
   |
   v
PENDING_VERIFICATION
   |
   v
Independent external read-back
   |
   +--> expected state observed -> COMPLETED
   +--> ambiguous/mismatch      -> UNVERIFIED
```

This is why `ALLOW` is not execution, an active Member grant is not effective authorization and HTTP `2xx` is not completion.

## What the demo proves

T3 Privacy Guard assumes the AI agent can be manipulated. The dashboard sends an actual textual prompt to a configured tool-calling model. The model can produce an unsafe structured proposal such as `host=attacker.example` plus `api_key`, but it cannot set a decision, identity, capability or secret. That proposal is persisted and evaluated independently by the T3N Rust/WASM policy, which returns `DENY`.

The Proposal Agent and Protected Executor are different authenticated T3N principals. The Proposal Agent receives only the evaluation grant. The Protected Executor receives only the protected execution/verification grant. Their DIDs are derived from their authenticated sessions, never hardcoded or supplied by the model.

For each principal, the gateway distinguishes two facts:

```text
Member grant
  = configured/read authorization document + validity window

Effective T3N access
  = authenticated principal calls checkDelegation({
      contract,
      pii_did: canonical Tenant DID,
      functions: exact minimum functions,
      scopes: exact minimum scopes
    })
```

`authorised=true` becomes effective `ACTIVE` / UI `Confirmed`. `authorised=false` becomes `DENIED`. Errors, timeouts and inconclusive payloads become `UNKNOWN`. `DENIED` and `UNKNOWN` always fail closed. A non-active Member grant can never produce effective `ACTIVE`.

A legitimate model proposal can receive `ALLOW`, but `ALLOW` still does not execute anything. An authenticated operator must explicitly authorize remediation. Spring signs a short-lived, one-time capability bound to the exact persisted action, decision, fields, logical private-data references, policy version/hash and authenticated Protected Executor DID. The gateway validates service authentication, signature, expiry, payload equality and replay state before T3N execution.

Private profile values are structural to T3N. The agent, React, Spring Boot and gateway APIs carry only logical references such as `verified_email`; the Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`, and T3N resolves the plaintext only during protected egress. The resolved value is never returned to the application.

A successful external HTTP response is **not** treated as completion. The backend first acquires a durable execution claim, the contract propagates the stable `requestId` as an idempotency key, accepted egress becomes `PENDING_VERIFICATION`, and a separate `verify-remediation` read-back must observe the closed expected state before Spring records `COMPLETED`. Ambiguous outcomes are `UNVERIFIED` and are never automatically re-executed.

## Architecture

```text
Untrusted prompt
      |
      v
Configured AI provider
      | structured proposal + logical private refs only
      v
React / Spring Boot
      |
      v
Node / TypeScript T3N Gateway
      |
      +--> authenticated Tenant session
      |       -> canonical Tenant DID / pii_did
      |
      +--> authenticated Proposal Agent session
      |       -> Member grant read-back
      |       -> checkDelegation(evaluate-action + exact scopes)
      |       -> T3N Rust/WASM policy
      |             DENY | REDACT | ALLOW
      |                              |
      |                       human authorization
      |                              |
      |                       one-time capability
      |                              |
      +--> authenticated Protected Executor session
              -> separate Member grant read-back
              -> checkDelegation(execute-remediation + verify-remediation + exact scopes)
              -> protected T3N execution
                       |
                PENDING_VERIFICATION
                       |
                independent read-back
                       |
              VERIFIED -> COMPLETED
              otherwise -> UNVERIFIED
```

- `frontend/`: React/Vite operator dashboard served by Nginx.
- `backend/`: Java 21/Spring Boot business API, operator sessions and durable business/remediation state.
- `t3n-gateway/`: isolated T3N SDK adapter, AI provider adapter, separate Tenant/Proposal/Executor sessions, delegation checks and anti-replay protection.
- `contracts/privacy-guard/`: Rust/WIT policy, closed private-reference mapping, protected remediation and independent verification for `wasm32-wasip2`.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; services are deployed independently in containers.

## Authority separation

| Responsibility | Authority |
|---|---|
| Understand prompt and propose an action | AI model |
| Authenticate Tenant, Proposal Agent and Protected Executor | Separate T3N sessions |
| Publish/resolve public Proposal Agent discoverability | T3N Agent Card registry |
| Describe configured principal restrictions | Tenant Member Delegation read-back |
| Prove current principal/function/scope authorization | Authenticated principal `checkDelegation()` |
| Decide allowed action/data/host | Rust/WASM policy + versioned private T3N KV policy |
| Approve business remediation | Authenticated operator |
| Prove exact approved execution | Short-lived one-time capability bound to Executor DID |
| Resolve approved private profile value | T3N protected execution boundary |
| Decide whether external side effect is complete | Independent read-back + Spring state machine |

The prompt is untrusted content. It is never an authorization source.

## Real AI agent boundary

The gateway supports an optional OpenAI-compatible tool-calling provider through:

```text
AI_PROVIDER=openai-compatible
AI_API_URL=<provider chat-completions endpoint>
AI_API_KEY=<runtime secret>
AI_MODEL=<tool-calling model>
```

`AI_PROVIDER=disabled` is the safe default. When disabled or unavailable, agent analysis fails closed; no fixture is promoted as live AI.

The model tool surface is limited to:

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

Unknown properties are rejected. The model cannot supply `decision`, `allow`, `override`, `approved`, `agent_did`, `executor_did`, `pii_did`, API keys, credentials, secrets, remediation capabilities or literal `{{profile...}}` markers.

## T3N identity, onboarding and authorization states

The dashboard deliberately keeps these concepts separate:

```text
Authenticated
  -> session proved control of credential and returned canonical DID

Registered
  -> public Proposal Agent Card resolved and matched that DID

Member grant
  -> Tenant-owned authorization document for principal/contract/functions/scopes/hosts/window

Effective T3N access
  -> principal's exact checkDelegation verdict at runtime
```

Agent Card registration is public discoverability. It is not contract authorization. Likewise, Member grant `ACTIVE` is not sufficient to render the system `Operational`.

Effective states are:

- `Confirmed`: `checkDelegation.authorised === true`;
- `Denied`: `authorised === false`;
- `Unknown`: error, timeout or inconclusive response.

The Proposal and Executor checks are independent. The Proposal check covers only `evaluate-action`; the Executor check covers only `execute-remediation` and `verify-remediation`. Neither result authorizes the other principal.

## Current policy vocabulary

| Action | Purpose | Minimum normal fields | Private reference |
|---|---|---|---|
| `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none |
| `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none |
| `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none |
| `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `verified_email` allowed |

Extra non-secret fields are minimized with `REDACT`. Forbidden secret fields are denied. Unsupported actions, purposes, hosts or private references fail closed.

## Versioned operational policy in private T3N KV

Contract `0.4.0` reads a canonical `PolicyDocument` from the private T3N KV map `privacy-guard-policy`. The document controls enabled actions, purpose, allowed hosts, normal field allowlists, supported logical private references, host requirement and whether human authorization is required.

Critical security invariants remain compiled into Rust/WASM and cannot be relaxed by KV configuration. This includes schema/size ceilings, fail-closed behavior, authenticated T3N identity boundaries, forbidden secret classes, the closed private-reference vocabulary and safe host validation.

Every valid policy decision carries:

```text
policyVersion
policyHash
requiresHumanAuthorization
```

The gateway stores immutable version snapshots, a `current` pointer and publication/rollback history. Missing, malformed, oversized or semantically invalid policy data fails closed. Human authorization and protected execution are bound to the same version/hash so a policy change after approval cannot silently reuse stale authority.

`policyHash` is provenance, not a hardware-attestation claim.

## Structural private-data boundary

The initial private reference is intentionally narrow:

```text
logical reference: verified_email
action/purpose:   notify-security / incident-notification
TEE mapping:       {{profile.verified_contacts.email.value}}
```

Where plaintext may exist:

```text
AI model                       NO
React / browser                NO
Spring Boot / H2               NO
Node gateway request/response  NO
Business audit/evidence        NO
T3N protected egress           YES, only while resolving the approved placeholder
Allowed external service       YES, as the intended recipient of the protected egress
```

Clients cannot submit arbitrary profile namespaces. `verified_email` on an unrelated action is minimized with `REDACT`; unknown references and literal placeholder strings are denied.

## Distributed remediation boundary

```text
REMEDIATION_AUTHORIZED
        |
        | pessimistic atomic claim
        v
EXECUTING
        |
        | protected external request with stable requestId
        v
PENDING_VERIFICATION
        |
        | independent verify-remediation read-back
        +----------------------------+
        |                            |
        v                            v
COMPLETED                       UNVERIFIED
```

Rules:

- only one application execution claim can be created per action;
- a fresh concurrent caller observes the existing `EXECUTING` claim instead of intentionally sending a second request;
- an HTTP 2xx is acceptance, never completion;
- `COMPLETED` requires read-back matching the same operation and closed expected state `REVOKED`;
- ambiguous outcomes become `UNVERIFIED` and are not automatically re-executed;
- the project does **not** claim external-provider exactly-once/at-most-once behavior merely because an idempotency key is supplied.

## Security boundaries

- `T3N_API_KEY`, `T3N_AGENT_API_KEY`, `T3N_EXECUTOR_API_KEY` and `AI_API_KEY` are gateway-only runtime secrets.
- `GATEWAY_SERVICE_TOKEN` is a separate service-to-service credential.
- `REMEDIATION_CAPABILITY_KEY` signs one-time human authorization proofs and is distinct from every T3N/provider/remediation credential.
- Canonical Tenant, Proposal Agent and Protected Executor DIDs come from authenticated T3N sessions.
- A public Agent Card is discoverability metadata and never grants functions, scopes, hosts or business authorization.
- Member Delegation read-back describes configured restrictions; it does not replace the principal's effective check.
- Delegation checks and delegated calls derive `pii_did` internally from the authenticated Tenant session.
- Proposal and Executor checks use minimum explicit functions/scopes, without wildcard broadening.
- The model proposes; Rust/WASM policy decides. Provider failure, invalid tool output, invalid/missing policy, `DENIED`/`UNKNOWN` effective access and T3N failure all fail closed.
- The model/application carry only logical private references; only the contract maps them to supported T3N profile markers.
- `ALLOW` + exact policy provenance + authenticated operator + explicit human authorization + valid one-time capability are required before protected remediation.
- Consumed capability nonces are persisted so replay protection survives gateway restart when `/data` is persistent.

See the threat model and claims matrix in [`docs/submission/README.md`](docs/submission/README.md).

## T3N operational status

The UI reports independent observed states instead of collapsing them into one “connected” flag:

```text
Gateway                    ONLINE / UNAVAILABLE
Tenant                     AUTHENTICATED / NOT AUTHENTICATED
Proposal Agent             AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Proposal Member grant      ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
Proposal effective access  CONFIRMED / DENIED / UNKNOWN
Protected Executor         AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Executor Member grant      ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
Executor effective access  CONFIRMED / DENIED / UNKNOWN
Onboarding                 REGISTERED / NOT_REGISTERED / MISMATCH / UNAVAILABLE
Contract                   RESOLVED / UNAVAILABLE
Proposal evaluation        READY / NOT READY
Protected remediation      READY / NOT READY
```

`Proposal evaluation` becomes ready only when Tenant and Proposal sessions are authenticated, the contract is resolved and Proposal effective access is confirmed. `Protected remediation` additionally requires the separate Protected Executor session and its effective access to be confirmed.

No message can report the T3N controls as operational solely because a Member grant exists.

## Evidence

The project distinguishes local controls from live T3N proof. It does not upgrade mocks, unit tests, grant read-backs or unexecuted scenarios into live evidence.

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

The live orchestrator:

1. authenticates Tenant, Proposal Agent and Protected Executor through the verified trust boundary;
2. resolves the contract and versioned policy;
3. provisions minimum independent Member grants;
4. calls `checkDelegation()` through the Proposal Agent for exact evaluation functions/scopes;
5. calls `checkDelegation()` through the Protected Executor for exact execution/verification functions/scopes;
6. fails unless both required effective states are `ACTIVE`;
7. runs the T3N testnet scenarios;
8. leak-scans generated evidence.

`docs/evidence/testnet-run.json` records only sanitized delegation proof:

```json
{
  "delegation": {
    "proposal": {
      "memberState": "ACTIVE",
      "effectiveState": "ACTIVE",
      "checkedFunctions": ["evaluate-action"],
      "checkedScopes": ["incident_id", "credential_id", "reason"]
    },
    "executor": {
      "memberState": "ACTIVE",
      "effectiveState": "ACTIVE",
      "checkedFunctions": ["execute-remediation", "verify-remediation"],
      "checkedScopes": ["incident_id", "credential_id", "reason"]
    }
  }
}
```

The complete Member Delegation document, credentials, private values and secrets are not frontend/evidence fields. `NOT_RUN` is never counted as `PASS`.

For live remediation proof, both action and verification endpoints must be configured/sealed and the Executor host allowlist contains only their derived HTTPS hosts. A live remediation scenario passes only after protected execution plus independent verification. An accepted 2xx without read-back cannot become a completion claim.

Profile-placeholder resolution remains `NOT_RUN` in public evidence until a compatible T3N testnet profile/user context actually executes it.

## Persistent T3N trust-manifest rollback protection

Before Tenant, Proposal Agent or Protected Executor authentication, the gateway verifies the official signed T3N trust manifest and persists the accepted manifest version as a monotonic high-water mark per network. `T3N_TRUST_FLOOR_STORE_PATH` defaults to `/data/t3n-trust-floor.json`; the file contains only public trust metadata, never API keys, cookies or session credentials.

When a floor exists, authentication calls `fetchTrustedManifest(network, { minVersion })`. A lower manifest is rejected. All three sessions share the same `TrustManifestFloorStore`, so they cannot establish independent rollback histories for the same network.

`Trust anchor VERIFIED` and `Rollback floor PERSISTED` describe cluster trust provenance, not per-request hardware attestation.

## Runtime configuration

Relevant names include:

```text
T3N_API_KEY
T3N_AGENT_API_KEY
T3N_EXECUTOR_API_KEY
T3N_CONTRACT_VERSION
T3N_POLICY_FILE
T3N_TRUST_FLOOR_STORE_PATH
OPERATOR_USERNAME
OPERATOR_PASSWORD
OPERATOR_SESSION_TIMEOUT
SESSION_COOKIE_SECURE
GATEWAY_SERVICE_TOKEN
REMEDIATION_CAPABILITY_KEY
REMEDIATION_CAPABILITY_TTL_SECONDS
REMEDIATION_REPLAY_STORE_PATH
AI_PROVIDER
AI_API_URL
AI_API_KEY
AI_MODEL
SECURITY_API_KEY
SECURITY_API_URL
SECURITY_VERIFICATION_URL
```

Use `.env.example` only as a variable-name template. Never commit Tenant, Proposal Agent or Protected Executor keys, provider keys, operator passwords, service tokens, capability keys, remediation credentials, private profile values or `.env` files.

## Pinned toolchain

- Node: `22.20.0-alpine3.22`
- React / React DOM: `19.3.0`
- Vite: `8.2.2`
- `@vitejs/plugin-react`: `6.1.1`
- TypeScript: `5.9.2`
- T3N SDK: **`5.2.0`**
- Express: `5.1.0`
- Maven image: `3.9.16-eclipse-temurin-21`
- Java runtime: `eclipse-temurin:21.0.12_8-jre`
- Nginx: `1.27.5-alpine3.21-slim`
- Rust contract: `0.4.0`, target `wasm32-wasip2`

## Local builds

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm test && npm run typecheck && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

The project continues to be operated after the challenge. Future handover provisions new credentials instead of transferring existing private keys.
