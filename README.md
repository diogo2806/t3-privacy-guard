# T3 Privacy Guard

**Enterprise trust runtime for AI agents on the Terminal 3 Network.**

T3 Privacy Guard is designed for a simple enterprise assumption: **the AI model can be useful and still be untrusted**. The model may analyze an incident and propose an action, but it is not allowed to become the authority that decides policy, selects trusted identities, grants itself delegation, retrieves private profile values directly or declares a critical side effect completed.

The central product thesis is:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

> **Judge / submission guide:** [`docs/submission/README.md`](docs/submission/README.md)  
> **Evidence reproduction:** [`docs/evidence/README.md`](docs/evidence/README.md)  
> **Adversarial matrix:** [`docs/evidence/scenario-matrix.md`](docs/evidence/scenario-matrix.md)

## What problem it solves

Enterprise agents are often given enough context and credentials to be useful. That creates a dangerous coupling: a prompt injection, compromised model or bad instruction can become data access or a real side effect if the same component is also trusted to authorize what it proposes.

T3 Privacy Guard breaks that coupling. The AI receives a deliberately narrow proposal surface. Security-sensitive authority is derived elsewhere and cannot be supplied by the model.

For private profile data, the application carries logical references such as `verified_email`, not the private value. The Rust/WASM contract maps a closed reference to the supported T3N profile marker only inside the protected execution boundary. React, Spring Boot, the model and normal gateway responses do not receive the resolved plaintext.

For delegation, the system does not equate a Tenant-side Member grant with effective authority. An active grant must also pass T3N `checkDelegation()` through the authenticated Proposal Agent or Protected Executor session. Only `authorised=true` produces effective access `ACTIVE`.

For side effects, an HTTP success response is not treated as business completion. The application records `COMPLETED` only after a separate read-back observes the expected closed external state.

## Where it applies

The current implementation is demonstrated through security incident response, but the trust pattern is broader. The same architecture is relevant anywhere an AI agent can recommend or trigger actions involving sensitive data or privileged operations, for example:

- security operations, where an agent can propose credential revocation, account isolation, incident recording or a security notification;
- HR or identity workflows, where an agent may need a verified attribute but should not receive the underlying private value;
- financial or compliance workflows, where policy and human authorization must remain independent from the model;
- support and operations agents, where outbound destinations and fields must be restricted to an explicit minimum;
- autonomous enterprise agents, where a useful model must not implicitly become the source of authorization.

The project does **not** claim that all of those vertical workflows are already implemented. They illustrate where the trust-runtime pattern can be applied.

## 60-second mental model

### Compromised-agent scenario

```text
Prompt injection
   |
   v
AI proposes:
- send api_key
- attacker.example
   |
   v
T3N Rust/WASM policy
   |
   v
DENY

No protected egress.
No model-controlled override.
```

### Legitimate-remediation scenario

```text
AI proposes minimum valid action
   |
   v
Proposal Agent authenticated
   |
   v
Member grant ACTIVE
   |
   v
T3N checkDelegation -> authorised=true
   |
   v
Effective access ACTIVE
   |
   v
T3N policy -> ALLOW
   |
   v
Authenticated human authorizes
   |
   v
Protected Executor authenticated
   |
   v
Executor Member grant + checkDelegation
   |
   v
Executor effective access ACTIVE
   |
   v
Short-lived one-time capability
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

This is why `ALLOW` is not execution, Member grant `ACTIVE` is not by itself effective access, and HTTP `2xx` is not completion.

## What the demo proves

T3 Privacy Guard assumes the AI agent can be manipulated. The dashboard sends an actual textual prompt to a configured tool-calling model. The model can produce an unsafe structured proposal such as `host=attacker.example` plus `api_key`, but it cannot set a decision, identity, capability or secret. That proposal is persisted and evaluated independently by the T3N Rust/WASM policy.

A legitimate model proposal can receive `ALLOW`, but `ALLOW` still does not execute anything. An authenticated operator must explicitly authorize remediation. Spring signs a short-lived one-time capability bound to the exact persisted action, decision, fields, logical private-data references, policy version/hash and authenticated Protected Executor DID. The gateway validates service authentication, signature, expiry, payload equality and replay state before T3N execution.

Private profile values are structural to T3N. The agent, React, Spring Boot and gateway APIs carry only logical references such as `verified_email`; the Rust/WASM contract maps that closed reference to `{{profile.verified_contacts.email.value}}`, and T3N resolves the plaintext only during protected egress. The resolved value is never returned to the application.

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
      +--> optional public A2A v1.0 -> evaluation only
      |
      +--> Tenant session ------------------------+
      |                                           |
      +--> Proposal Agent session                 | pii_did
      |      |                                     |
      |      +--> Member grant                    |
      |      +--> checkDelegation ----------------+
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
   DENY | REDACT | ALLOW
                    |
              human authorization
                    |
              one-time capability
         bound to Protected Executor DID
                    |
              atomic execution claim
                    |
                    v
        protected execution in T3N
                    |
             PENDING_VERIFICATION
                    |
                    v
          independent T3N read-back
                    |
        VERIFIED -> COMPLETED
        otherwise -> UNVERIFIED
```

- `frontend/`: React/Vite operator dashboard served by Nginx.
- `backend/`: Java 21/Spring Boot business API, operator sessions and durable business/remediation state.
- `t3n-gateway/`: isolated T3N SDK adapter, AI provider adapter, optional public A2A evaluation adapter, separate Tenant/Proposal Agent/Protected Executor sessions, delegation verification and anti-replay protection.
- `contracts/privacy-guard/`: Rust/WIT policy, closed private-reference mapping, protected remediation and independent verification for `wasm32-wasip2`.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; services are deployed independently in containers.

## Authority separation

| Responsibility | Authority |
|---|---|
| Understand prompt and propose an action | AI model |
| Request public analysis/evaluation | External A2A client, when enabled |
| Authenticate Tenant identity | T3N Tenant session |
| Authenticate proposal identity | T3N Proposal Agent session |
| Authenticate protected execution identity | T3N Protected Executor session |
| Publish/resolve public agent discoverability | T3N Agent Card registry |
| Record least-privilege grant intent | Tenant-side Member Delegation |
| Confirm effective principal authority | T3N `checkDelegation()` through the authenticated principal |
| Decide allowed action/data/host | Rust/WASM policy + versioned private T3N KV policy |
| Approve business remediation | Authenticated operator |
| Prove an exact approved execution | Short-lived one-time capability bound to Executor DID |
| Resolve approved private profile value | T3N protected execution boundary |
| Decide whether external side effect is complete | Independent read-back + Spring state machine |

The prompt is untrusted content. It is never an authorization source. An A2A client can request evaluation but cannot become the authorization source either.

## Real AI agent boundary

The gateway supports an optional OpenAI-compatible tool-calling provider:

```text
AI_PROVIDER=openai-compatible
AI_API_URL=<provider chat-completions endpoint>
AI_API_KEY=<runtime secret>
AI_MODEL=<tool-calling model>
```

`AI_PROVIDER=disabled` is the safe default. When disabled or unavailable, agent analysis fails closed; no fixture is promoted as live AI.

The only model tool surface is:

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

Unknown properties are rejected. The model cannot supply `decision`, `allow`, `override`, `approved`, `agent_did`, `pii_did`, API keys, credentials, secrets, remediation capabilities or literal `{{profile...}}` markers. Canonical identities come only from authenticated T3N sessions.

Real private values must never be placed in demo prompts; the model asks only for an enumerated logical category when a supported private value is needed.

## T3N identity, onboarding and effective delegation

The runtime deliberately separates identity, discoverability, grant records and effective authority.

```text
Proposal Agent API key
        |
        v
authenticated Proposal Agent session
        |
        v
canonical did:t3n:... from session
        |
        +--> public Agent Card
        |      |
        |      v
        |   REGISTERED / NOT_REGISTERED / MISMATCH / UNAVAILABLE
        |
        +--> matching Member grant
               |
               +--> ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
               |
               | only when ACTIVE
               v
         T3N checkDelegation
               |
               +--> authorised=true  -> effective ACTIVE
               +--> authorised=false -> effective INCOMPLETE
               +--> error/invalid    -> effective UNKNOWN
```

The Protected Executor performs the same Member-grant-to-`checkDelegation()` validation independently with its own authenticated T3N credential/DID.

`checkDelegation()` receives only server-derived security inputs:

- `contract`: the canonical resolved contract id;
- `pii_did`: `tenantSession.getTenantDid()` from the authenticated Tenant session;
- `functions`: exact functions observed in the matching Member grant;
- `scopes`: exact scopes observed in the matching Member grant.

The browser cannot supply the Tenant DID, Proposal Agent DID, Protected Executor DID, contract id used for authorization, grant functions/scopes or an authorization verdict. No wildcard scope/function is introduced by the status path.

Runtime semantics:

| Member state | Platform verdict | Effective state | Ready? |
|---|---|---|---|
| `ACTIVE` | `authorised=true` | `ACTIVE` | potentially, if all other controls pass |
| `ACTIVE` | `authorised=false` | `INCOMPLETE` | no |
| `ACTIVE` | unavailable/malformed | `UNKNOWN` | no |
| `SCHEDULED` | not called | `INCOMPLETE` | no |
| `REVOKED` | not called | `INCOMPLETE` | no |
| `NOT_GRANTED` | not called | `INCOMPLETE` | no |
| `UNKNOWN` | not called | `UNKNOWN` | no |

The status API exposes only bounded/sanitized `satisfied` and `missing` labels from the platform verdict. It never forwards raw SDK objects or credentials.

### Public Agent Card

`buildAgentCardForSession(...)` uses only `AgentSession.getAgentDid()` as the identity source. The card always advertises the supported `DID` service for the same canonical DID, `active: true` and `x402Support: false`. When and only when `A2A_PUBLIC_URL` is configured as a valid public HTTPS `/a2a` endpoint, the T3N Agent Card also advertises the `A2A` service at the real `/.well-known/agent-card.json` discovery URL with protocol version `1.0`. It never advertises MCP, x402 payment support, unsupported trust claims or private/internal gateway endpoints. Sensitive metadata keys and private-key-shaped values are rejected.

Operational commands from `t3n-gateway/`:

```bash
npm run agent:card:verify    # read-only; does not publish or grant permissions
npm run agent:card:publish   # explicit mutable T3N operation; may consume credits
```

Agent Card states are discoverability evidence only:

- `REGISTERED`: resolved card matches the authenticated Proposal Agent DID and the locally configured supported service schema;
- `NOT_REGISTERED`: no card was found;
- `MISMATCH`: a card was returned but failed closed validation, including a configured/observed A2A service mismatch;
- `UNAVAILABLE`: resolution could not be verified.

`REGISTERED` does not mean delegated, effectively authorized, TEE-attested or permitted to execute a contract function.

## A2A evaluation service

A2A is an optional public interoperability surface for **evaluation only**. Set `A2A_PUBLIC_URL` to the externally reachable HTTPS `/a2a` endpoint. When configured, the gateway exposes:

```text
GET  /.well-known/agent-card.json
POST /a2a
```

The public Agent Card declares one skill: **A2A evaluation service**. External agents can request analysis and a T3N policy decision. Protected remediation remains operator-authorized and is not exposed through A2A.

The adapter uses A2A protocol version `1.0` with JSON-RPC `SendMessage`. It accepts one bounded `ROLE_USER` text part, applies a 16 KiB request-body ceiling, a 4,000-character prompt ceiling and basic in-memory rate limiting. Unknown fields and unsupported operations/content types fail closed. The client cannot supply `agent_did`, `pii_did`, `decision`, authorization state, remediation capability, credentials or Protected Executor identity.

The public flow is intentionally narrow:

```text
external A2A message
      |
      v
prompt privacy guard
      |
      v
existing AgentService
      | structured proposal only
      v
existing T3N evaluate-action
      | server-derived Proposal Agent DID + Tenant pii_did
      v
proposal + decision + reason code + policy version/hash + Proposal Agent DID
```

Sensitive prompts are rejected before a remote AI provider is called. Provider/schema failure and T3N evaluation failure return sanitized errors without echoing prompt/credentials. A2A has no endpoint for human authorization, `execute-remediation`, `verify-remediation` or capability issuance.

Status language is intentionally conservative: `Configured` means local URL validation passed; `Published` means A2A was observed in the resolved public T3N Agent Card. Neither is called `verified live` unless an external reachability test actually occurs. The current status check states explicitly when that live test was not performed.

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
policyVersion   exact immutable policy version
policyHash      SHA-256 of the canonical policy document
requiresHumanAuthorization
```

The provisioner stores immutable snapshots as `version:<version>`, maintains `current`, and records publication/rollback history. Publishing different canonical content under an existing version is rejected. Rollback is explicit. Missing, malformed, oversized or semantically invalid policy fails closed.

Policy provenance follows the decision through Spring persistence, API, dashboard, evidence metadata and remediation capability. Protected remediation re-reads the active policy and requires the exact approved version/hash. A policy change after authorization invalidates stale approval.

`policyHash` is provenance, not a hardware-attestation claim.

## Enterprise scenario catalog

| Scenario | Proposed action | What the demo proves |
|---|---|---|
| Credential compromised | `revoke-credential` | Prompt-injection denial plus minimum-scope revocation with human authorization, protected execution and independent read-back. |
| Account takeover | `isolate-account` | The model can propose isolation while T3N independently evaluates action, fields, purpose and destination. |
| Record security incident | `create-incident` | Incident recording can be evaluated without outbound egress. |
| Notify security contact | `notify-security` | The model requests only logical `verified_email`; no plaintext email or raw profile placeholder belongs in browser/model input. |

Selecting a scenario changes only local demonstration context and the editable prompt; it does not authorize anything or predict the T3N result. Switching scenarios clears the previous result before a new analysis.

The current complete execution/read-back contract verifies only the closed external state `REVOKED`, so protected execution controls are exposed only for an actual `revoke-credential` proposal. The other actions remain genuine policy-evaluation scenarios rather than falsely claimed end-to-end executors.

## Structural private-data boundary

```text
logical reference: verified_email
action/purpose:   notify-security / incident-notification
TEE mapping:       {{profile.verified_contacts.email.value}}
```

The literal marker is created inside Rust/WASM from a closed allowlist. Clients cannot submit arbitrary profile namespaces. Spring persists only the reference name, never the email address. Human authorization capabilities bind the private-reference set so it cannot be changed after approval.

Plaintext visibility:

```text
AI model                       NO
React / browser                NO
Spring Boot / H2               NO
Node gateway request/response  NO
Business audit/evidence        NO
T3N protected egress           YES, only while resolving the approved placeholder
Allowed external service       YES, as the intended recipient
```

`PlaceholderDenied`, `PlaceholderUnknown` and `PlaceholderNoUserContext` fail closed. Upstream responses are reduced to operation/status metadata before leaving the contract.

## Distributed remediation boundary

```text
REMEDIATION_AUTHORIZED
        |
        | pessimistic atomic claim
        v
EXECUTING
        |
        | requestId as stable Idempotency-Key
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
- a fresh concurrent caller observes the existing `EXECUTING` claim instead of sending a second request;
- HTTP 2xx is acceptance, never completion;
- `COMPLETED` requires read-back matching the same `operation_id` and closed expected state `REVOKED`;
- timeout after send, missing operation id, mismatched request id, unavailable verification or contradictory read-back becomes `UNVERIFIED`;
- `UNVERIFIED` may be re-verified when an operation id exists, but is never automatically re-executed;
- persisted remediation state can be read after reload/restart without causing egress or verification;
- the project does **not** claim exactly-once/at-most-once behavior from an external provider merely because an idempotency key is supplied.

## Security boundaries

- Operator login is an application identity, not a T3N or AI-provider identity.
- `T3N_API_KEY`, `T3N_AGENT_API_KEY`, `T3N_EXECUTOR_API_KEY` and `AI_API_KEY` are gateway-only runtime secrets and are never returned to the browser.
- `GATEWAY_SERVICE_TOKEN` is a separate service-to-service credential.
- `REMEDIATION_CAPABILITY_KEY` signs one-time human authorization proofs and is distinct from every T3N/provider/remediation credential.
- Canonical Tenant, Proposal Agent and Protected Executor DIDs come from authenticated T3N sessions.
- Agent Card is discoverability metadata and never grants functions, scopes, hosts or business authorization.
- Public A2A accepts evaluation requests only; it cannot issue human authorization, remediation capabilities or Protected Executor credentials and cannot execute protected remediation.
- Member Delegation is an observed grant record, not an effective verdict.
- Effective delegation is checked through the authenticated grantee client and fails closed on negative or unavailable verdicts.
- Delegated calls derive `pii_did` internally from the authenticated Tenant session.
- The model proposes; Rust/WASM policy decides. Provider failure, invalid tool output, invalid/missing versioned policy and T3N failure all fail closed.
- The model/application carry only logical private references; only the contract maps them to supported T3N profile markers.
- `ALLOW` + exact policy provenance + authenticated operator + explicit human authorization + valid one-time capability are required before protected remediation.
- Consumed capability nonces are persisted at `REMEDIATION_REPLAY_STORE_PATH` so replay protection survives gateway restart when `/data` is persistent.

See the threat model and claims matrix in [`docs/submission/README.md`](docs/submission/README.md).

## Runtime configuration

Relevant names include:

```text
T3N_API_KEY
T3N_AGENT_API_KEY
T3N_EXECUTOR_API_KEY
T3N_CONTRACT_VERSION
T3N_CONTRACT_NUMERIC_ID
T3N_POLICY_FILE
T3N_TRUST_FLOOR_STORE_PATH
A2A_PUBLIC_URL
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

`T3N_CONTRACT_VERSION` is `0.4.0` for the versioned-policy contract. `T3N_POLICY_FILE` points to the local source document used by the explicit policy provisioning script; the active runtime policy is loaded from private T3N KV.

`A2A_PUBLIC_URL` is optional. When set it must be the externally reachable HTTPS `/a2a` endpoint without credentials, query parameters or fragments. It enables the public A2A adapter and causes the T3N Agent Card publication/verification path to require the matching A2A discovery service.

`SECURITY_API_URL` is the protected action endpoint. `SECURITY_VERIFICATION_URL` is the independent read-back endpoint. Both are seeded into the T3N private map by the setup script; the verification endpoint is not a browser/backend credential.

Business APIs require the Spring Security operator session and CSRF protection. The browser never receives T3N keys, AI provider keys, internal service token, remediation capability, remediation credential or resolved profile PII.

## T3N operational status

The dashboard reports these facts independently:

```text
Gateway                    ONLINE / UNAVAILABLE
Tenant                     AUTHENTICATED / NOT AUTHENTICATED
Proposal Agent             AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Protected Executor         AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Agent onboarding           REGISTERED / NOT_REGISTERED / MISMATCH / UNAVAILABLE
A2A evaluation service     PUBLISHED / CONFIGURED NOT PUBLISHED / NOT CONFIGURED
A2A endpoint live test     NOT PERFORMED by the status check
Contract                   RESOLVED / UNAVAILABLE
Proposal Member grant      ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
Proposal platform verdict  AUTHORIZED / NOT AUTHORIZED / UNAVAILABLE / NOT CHECKED
Proposal effective access  ACTIVE / INCOMPLETE / UNKNOWN
Executor Member grant      ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
Executor platform verdict  AUTHORIZED / NOT AUTHORIZED / UNAVAILABLE / NOT CHECKED
Executor effective access  ACTIVE / INCOMPLETE / UNKNOWN
```

The control plane is reported `Operational` only when Tenant, Proposal Agent and Protected Executor authentication are ready, the contract is resolved, and **both effective delegation states are `ACTIVE`**. Member grant `ACTIVE` alone is insufficient. A2A publication is displayed separately and is not a prerequisite for protected operator workflows.

`RESOLVED` means contract id/version were resolved. It is not hardware attestation. Functions, scopes and allowed hosts come from the observed grant; sanitized `satisfied`/`missing` labels come from T3N's effective-delegation verdict.

## Policy and remediation exports

The Rust contract exports:

```text
evaluate-action
execute-remediation
verify-remediation
```

`evaluate-action` returns the exact policy version/hash used by the TEE. `execute-remediation` requires the approved version/hash and revalidates them against current private KV policy before protected egress. `verify-remediation` independently checks external operation/state data. A capability is rejected when its signed incident/action/decision/request/action/resource/purpose/fields/privateRefs/policyVersion/policyHash/Executor DID differ from the request, when expired or when its nonce was already consumed.

## Evidence

The project distinguishes local controls from live T3N proof. It does not upgrade mocks, unit tests or unexecuted scenarios into live evidence.

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

Generated artifacts are `docs/evidence/deployment-manifest.json` and `docs/evidence/testnet-run.json`. The orchestrator binds WASM SHA-256, canonical DIDs, contract id/version and policy version/hash and fails on mismatch, scenario `FAIL` or configured secret leakage. `NOT_RUN` is never counted as `PASS`.

Agent Card metadata proves discoverability only. If `A2A` appears in `agentCardServices`, the evidence proves that the resolved T3N Agent Card advertised the configured A2A discovery service at verification time; that observation does not by itself prove public endpoint reachability. Member grant status proves the observed grant record/window only. Runtime effective access is derived from the authenticated principal-side `checkDelegation()` verdict and is never inferred from registration or a grant record alone.

For live remediation proof, both `SECURITY_API_URL` and `SECURITY_VERIFICATION_URL` must be configured/sealed and the Executor grant includes only their derived HTTPS hosts. A live remediation scenario passes only on protected execution plus independent verification. An accepted 2xx without read-back cannot become a passing completion claim.

Profile-placeholder resolution remains `NOT_RUN` in public evidence until a compatible T3N testnet profile/user context actually executes it. Local tests prove the closed-reference architecture but are not mislabeled as live profile-resolution evidence.

## Persistent T3N trust-manifest rollback protection

Before Tenant, Proposal Agent or Protected Executor authentication, the gateway verifies the official signed T3N trust manifest and persists the accepted manifest version as a monotonic high-water mark per network. `T3N_TRUST_FLOOR_STORE_PATH` defaults to `/data/t3n-trust-floor.json`; the file contains only public trust metadata (`network`, accepted version and timestamp), never API keys, cookies or session credentials.

When a floor exists, authentication calls `fetchTrustedManifest(network, { minVersion })`. A lower manifest is rejected, the floor is never silently decreased, and malformed/unreadable persisted state fails closed instead of resetting rollback history. Tenant, Proposal Agent and Protected Executor sessions share the same `TrustManifestFloorStore` instance in the gateway runtime.

Evidence wording remains precise: `Trust anchor VERIFIED` means the signed manifest established the cluster trust boundary; `Rollback floor PERSISTED` means the version high-water mark was durably stored and reused across restarts. Neither is described as per-request hardware attestation.

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

## Environment

Use `.env.example` only as a variable-name template. Never commit Tenant keys, Proposal Agent keys, Protected Executor keys, AI provider keys, operator passwords, service tokens, capability keys, remediation credentials, private profile values or `.env` files.

The project will continue to be operated after the challenge. Future handover provisions new credentials instead of transferring existing private keys.
