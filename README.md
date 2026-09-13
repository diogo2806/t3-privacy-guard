# T3 Privacy Guard

**Enterprise trust runtime for AI agents on the Terminal 3 Network.**

T3 Privacy Guard is designed for a simple enterprise assumption: **the AI model can be useful and still be untrusted**. The model may analyze an incident and propose an action, but it is not allowed to become the authority that decides policy, selects trusted identities, retrieves private profile values directly, or declares a critical side effect completed.

The product separates those responsibilities across independent controls:

```text
Untrusted AI
    |
    | proposes
    v
Proposal Agent effective T3N access
    |
    v
T3N policy / Rust WASM
    |
    | DENY / REDACT / ALLOW
    v
Human authorization
    |
    | approves business intent + Protected Executor DID
    v
One-time execution capability
    |
    v
Protected Executor effective T3N access
    |
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

For T3N authorization, the system also separates what is configured from what the platform actually authorizes. An `ACTIVE` Member grant is document state only. The authenticated Proposal Agent and Protected Executor must each call `checkDelegation` for the exact contract, canonical tenant `pii_did`, functions and minimum scopes required by that principal. `authorised=false`, an exception or an unexpected response fails closed and cannot be rendered as operational readiness.

For private profile data, the application carries logical references such as `verified_email`, not the private value. The Rust/WASM contract maps a closed reference to the supported T3N profile marker only inside the protected execution boundary. React, Spring Boot, the model and normal gateway responses do not receive the resolved plaintext.

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

A judge should be able to understand the system through two opposite scenarios.

### 1. Compromised-agent scenario

```text
Prompt injection
   |
   v
AI proposes:
- send api_key
- attacker.example
   |
   v
Proposal Agent Member grant ACTIVE
+ effective T3N access CONFIRMED
   |
   v
T3N Rust/WASM policy
   |
   v
DENY

No protected egress.
No model-controlled override.
```

### 2. Legitimate-remediation scenario

```text
AI proposes minimum valid action
   |
   v
Proposal effective access CONFIRMED
   |
   v
T3N policy -> ALLOW
   |
   v
Authenticated human authorizes
   |
   v
Short-lived one-time capability
bound to Protected Executor DID
   |
   v
Executor effective access CONFIRMED
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

This is why `ALLOW` is not the same thing as execution, an observed grant is not the same thing as effective authorization, and HTTP `2xx` is not the same thing as completion.

## What the demo proves

T3 Privacy Guard assumes the AI agent can be manipulated. The dashboard sends an actual textual prompt to a configured tool-calling model. The model can produce an unsafe structured proposal such as `host=attacker.example` plus `api_key`, but it cannot set a decision, identity, capability or secret. That proposal is persisted and evaluated independently by the T3N Rust/WASM policy, which returns `DENY`.

The Proposal Agent uses its own authenticated T3N credential/DID and is restricted to `evaluate-action`. Before evaluation is considered ready, the gateway requires both an active Proposal Member grant and a principal-side `checkDelegation` result with `authorised=true` for the exact contract, tenant DID and minimum scopes. The tenant session is never used as a substitute for that delegated-principal check.

A legitimate model proposal can receive `ALLOW`, but `ALLOW` still does not execute anything. An authenticated operator must explicitly authorize remediation. Immediately before execution the Spring backend signs a short-lived, one-time capability bound to the exact persisted action, decision, fields, logical private-data references, the exact policy version/hash and the authenticated Protected Executor DID. The Executor uses a separate T3N credential/DID and its own least-privilege Member grant for `execute-remediation` + `verify-remediation`. Protected remediation is considered ready only when the Executor's principal-side `checkDelegation` also returns `authorised=true` for the exact restrictions. The gateway validates service authentication, signature, expiry, payload equality and replay state before T3N execution.

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
      +--> authenticated Proposal Agent DID + tenant pii_did
      |       | Member grant ACTIVE
      |       | checkDelegation(evaluate-action + exact scopes) = authorised
      |       v
      |    T3N / Rust WASM policy
      |       DENY | REDACT | ALLOW
      |                        |
      |                  human authorization
      |                        |
      |                  one-time capability
      |                  bound to Executor DID
      |                        |
      +--> authenticated Protected Executor DID
              | Member grant ACTIVE
              | checkDelegation(execute-remediation + verify-remediation + exact scopes) = authorised
              v
        protected execution in T3N
              |
        PENDING_VERIFICATION
              |
        independent T3N read-back
              |
        VERIFIED -> COMPLETED
        otherwise -> UNVERIFIED
```

- `frontend/`: React/Vite operator dashboard served by Nginx.
- `backend/`: Java 21/Spring Boot business API, operator sessions and durable business/remediation state.
- `t3n-gateway/`: isolated T3N SDK adapter, AI provider adapter, separate tenant/Proposal/Executor sessions, effective-delegation verification and anti-replay protection.
- `contracts/privacy-guard/`: Rust/WIT policy, closed private-reference mapping, protected remediation and independent verification for `wasm32-wasip2`.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; services are deployed independently in containers.

## Authority separation

The architecture deliberately prevents the model from owning security authority.

| Responsibility | Authority |
|---|---|
| Understand prompt and propose an action | AI model |
| Authenticate tenant, Proposal Agent and Protected Executor identities | Separate T3N sessions |
| Observe configured Member grants | Tenant Member Delegation read-back |
| Prove effective delegated access for exact functions/scopes | Principal-side T3N `checkDelegation` |
| Publish/resolve public agent discoverability | T3N Agent Card registry |
| Decide allowed action/data/host | Rust/WASM policy + versioned private T3N KV policy |
| Approve business remediation | Authenticated operator |
| Prove an exact approved execution | Short-lived one-time capability bound to Protected Executor DID |
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

Unknown properties are rejected. In particular the model cannot supply `decision`, `allow`, `override`, `approved`, `agent_did`, `pii_did`, API keys, credentials, secrets, remediation capabilities or literal `{{profile...}}` markers. `agent_did` comes only from the authenticated Proposal Agent session, the Protected Executor DID comes only from its authenticated session, and `pii_did` only from the authenticated tenant session.

Real private values must never be placed in demo prompts; the model asks only for an enumerated logical category when a supported private value is needed.

## Public T3N Agent onboarding and discoverability

The Proposal Agent has deliberately separate states: **authenticated**, **registered**, **Member grant**, and **effective access**. Authentication proves control of the configured Proposal credential and yields the canonical Agent DID. Registration proves that a public Agent Card for that same DID can be resolved from T3N. Member Delegation is the tenant/data-owner grant document. Effective access is the independent principal-side T3N authorization verdict for the exact operation. Registration and grant read-back never imply effective access by themselves.

The onboarding/authorization flow is:

```text
separate T3N Proposal Agent credential
        |
        v
authenticated AgentSession
        |
        v
canonical did:t3n:... from the session
        |
        +--> deterministic safe Agent Card
        |          |
        |          v
        |       T3N hosted public card
        |          |
        |          v
        |       REGISTERED / negative onboarding state
        |
        +--> Member grant ACTIVE
                   |
                   v
             checkDelegation
                   |
                   v
       effective access CONFIRMED / DENIED / UNKNOWN
```

`buildAgentCardForSession(...)` uses only `AgentSession.getAgentDid()` as the identity source. The card advertises the EIP-8004 registration type used by the installed T3N tooling, one `DID` service pointing to the same canonical DID, `active: true` and `x402Support: false`. It does not advertise A2A, MCP, x402 payment support or private/internal gateway endpoints that this project does not actually expose. Sensitive metadata keys and private-key-shaped values are rejected, and both generated and resolved cards are bounded by the hosted-card size limit.

Operational commands from `t3n-gateway/`:

```bash
npm run agent:card:verify    # read-only; does not publish or grant permissions
npm run agent:card:publish   # explicit mutable T3N operation; may consume credits
```

The publish command authenticates the agent, derives the DID from that session, writes the safe card locally, invokes the installed T3N CLI `agent host-card`, then performs read-only verification until the card resolves as `REGISTERED` or fails. It never takes a DID from `.env` as the canonical identity.

Runtime/evidence states are intentionally precise:

- `REGISTERED`: a valid public card resolved and its DID/service matches the authenticated Proposal Agent DID;
- `NOT_REGISTERED`: the public card endpoint returned no card for the DID;
- `MISMATCH`: a card was returned but failed the closed schema/DID/service validation;
- `UNAVAILABLE`: authenticated DID or public resolution could not be verified at that moment;
- Member grant `ACTIVE`: the observed tenant delegation document has a currently valid grant, but this alone does not prove effective authorization;
- Effective access `CONFIRMED`: the authenticated delegated principal's exact `checkDelegation` returned `authorised=true` while the Member grant is active;
- Effective access `DENIED`: the exact platform check returned `authorised=false`;
- Effective access `UNKNOWN`: the platform check failed or returned an unexpected result.

The dashboard shows onboarding, Member grant and Effective T3N access separately for the Proposal Agent, and Member grant/effective access separately for the Protected Executor. `DENIED` and `UNKNOWN` never use a positive operational state. Evidence may include the public card URI, SHA-256 of the exact resolved card, verification timestamp and declared service names. Those values are public discoverability provenance, not authorization and not hardware attestation.

## Current policy vocabulary

The current Rust policy contains four concrete security actions:

| Action | Purpose | Minimum normal fields | Private reference |
|---|---|---|---|
| `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none |
| `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none |
| `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none |
| `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `verified_email` allowed |

Extra non-secret fields are minimized with `REDACT`. Forbidden secret fields are denied. Unsupported actions, purposes, hosts or private references fail closed.

## Versioned operational policy in private T3N KV

The mutable operational rule set is no longer hardcoded as application state. Contract `0.4.0` reads a canonical `PolicyDocument` from the private T3N KV map `privacy-guard-policy`. The document controls enabled actions, purpose, allowed hosts, normal field allowlists, supported logical private references, host requirement and whether human authorization is required.

Critical security invariants remain compiled into Rust/WASM and cannot be relaxed by KV configuration. This includes schema/size ceilings, fail-closed behavior, authenticated T3N identity boundaries, forbidden secret classes, the closed private-reference vocabulary and safe host validation. A policy document cannot make `api_key`, passwords, tokens or private keys valid outbound fields and cannot bypass delegation or identity checks.

Every valid policy decision carries:

```text
policyVersion   exact immutable policy version
policyHash      SHA-256 of the canonical policy document
requiresHumanAuthorization
```

The gateway provisioner stores immutable snapshots as `version:<version>`, maintains `current`, and records publication/rollback history. Publishing different canonical content under an existing version is rejected. Rollback is explicit through `T3N_POLICY_ROLLBACK_VERSION` and may target only a version already persisted in the private map. A missing, malformed, oversized or semantically invalid policy fails closed.

Policy provenance follows the decision through Spring persistence, the API, the dashboard, deployment/evidence metadata and the remediation capability. Protected remediation re-reads the active T3N policy and requires the exact version/hash that was approved. If policy changes after authorization, the old approval cannot be silently reused; the action must be evaluated again.

`policyHash` is provenance, not a hardware-attestation claim.

## Enterprise scenario catalog

The Protection demo exposes those four policy actions as business-readable, synthetic presets. Selecting a card only changes local demonstration context and the editable prompt; it does not call an API, authorize anything or predict the T3N result.

| Scenario | Proposed action | What the demo proves |
|---|---|---|
| Credential compromised | `revoke-credential` | Prompt-injection denial plus a separate minimum-scope revocation path with human authorization, protected execution and independent read-back. |
| Account takeover | `isolate-account` | The model can propose isolation with synthetic identifiers while T3N independently evaluates action, fields, purpose and destination. |
| Record security incident | `create-incident` | Incident recording can be evaluated without outbound egress; adding an unexpected destination remains subject to T3N policy. |
| Notify security contact | `notify-security` | The model requests only logical `verified_email`; no plaintext email or raw `{{profile.*}}` placeholder belongs in browser/model input. |

The current complete execution/read-back contract verifies the closed external state `REVOKED`, so the dashboard exposes protected execution controls only for an actual `revoke-credential` proposal. `isolate-account`, `create-incident` and `notify-security` remain genuine policy-evaluation scenarios; the UI does not claim a verified executor for them.

Switching scenarios clears the previous scenario result in the browser before a new analysis. This prevents a prior decision or execution state from being visually attributed to a different preset.

## Structural private-data boundary

The initial private reference is intentionally narrow:

```text
logical reference: verified_email
action/purpose:   notify-security / incident-notification
TEE mapping:       {{profile.verified_contacts.email.value}}
```

The literal marker is created inside Rust/WASM from a closed allowlist. Clients cannot submit arbitrary profile namespaces. `verified_email` on an unrelated action is minimized with `REDACT`; unknown references and literal placeholder strings are denied. Spring persists only the reference name, never the email address. Human authorization capabilities bind the private-reference set so it cannot be changed after approval.

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

`PlaceholderDenied`, `PlaceholderUnknown` and `PlaceholderNoUserContext` fail closed. Upstream responses are reduced to operation/status metadata before leaving the contract, so an echoed private value is not returned to the application.

## Distributed remediation boundary

The persistent state machine is:

```text
REMEDIATION_AUTHORIZED
        |
        | pessimistic atomic claim
        v
EXECUTING
        |
        | external request with requestId as stable Idempotency-Key
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
- an execution acknowledgement or any HTTP 2xx is only acceptance, never completion;
- `COMPLETED` requires read-back matching the same `operation_id` and the closed expected state `REVOKED`;
- a timeout after send, missing operation id, mismatched request id, unavailable verification or contradictory read-back becomes `UNVERIFIED`;
- `UNVERIFIED` may be re-verified when an operation id exists, but is never automatically re-executed;
- persisted remediation state can be read after reload/restart without causing egress or a verification attempt;
- the project does **not** claim exactly-once/at-most-once behavior from an external provider merely because an idempotency key is supplied. Provider support is required for that guarantee.

## Security boundaries

- Operator login is an application identity, not a T3N or AI-provider identity.
- `T3N_API_KEY`, `T3N_AGENT_API_KEY`, `T3N_EXECUTOR_API_KEY` and `AI_API_KEY` are gateway-only runtime secrets and are never returned to the browser.
- Proposal Agent and Protected Executor credentials/DIDs are separate from each other and from the tenant.
- `GATEWAY_SERVICE_TOKEN` is a separate service-to-service credential.
- `REMEDIATION_CAPABILITY_KEY` signs one-time human authorization proofs and is distinct from every T3N/provider/remediation credential.
- Canonical tenant/Proposal/Executor DIDs come from authenticated T3N sessions.
- A public Agent Card is discoverability metadata and never grants functions, scopes, hosts or business authorization.
- Delegated calls and `checkDelegation` derive `pii_did` internally from the authenticated tenant session.
- Member Delegation restricts contract, functions, scopes, hosts and validity but is not treated as sufficient proof of effective authorization.
- Effective authorization is confirmed only by principal-side T3N `checkDelegation` for exact least-privilege restrictions; DENIED/UNKNOWN fail closed.
- The model proposes; Rust/WASM policy decides. Provider failure, invalid tool output, invalid/missing versioned policy and T3N failure all fail closed.
- The model/application carry only logical private references; only the contract maps them to supported T3N profile markers.
- `ALLOW` + exact policy provenance + authenticated operator + explicit human authorization + valid one-time capability + confirmed Protected Executor effective access are required before protected remediation.
- Consumed capability nonces are persisted at `REMEDIATION_REPLAY_STORE_PATH` so replay protection survives gateway restart when `/data` is persistent.

See the threat model and claims matrix in [`docs/submission/README.md`](docs/submission/README.md).

## Runtime configuration

Relevant names include:

```text
T3N_CONTRACT_VERSION
T3N_POLICY_FILE
T3N_AGENT_API_KEY
T3N_EXECUTOR_API_KEY
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

`T3N_AGENT_API_KEY` authenticates the Proposal Agent and must not be granted protected remediation functions. `T3N_EXECUTOR_API_KEY` authenticates the separate Protected Executor and must receive only the execution/verification functions and hosts it needs.

`SECURITY_API_URL` is the protected action endpoint. `SECURITY_VERIFICATION_URL` is the independent read-back endpoint. Both are seeded into the T3N private map by the setup script; the verification endpoint is not a browser/backend credential.

Business APIs require the Spring Security operator session and CSRF protection. The browser never receives T3N keys, AI provider keys, internal service token, remediation capability, remediation credential or resolved profile PII.

## T3N operational status

The dashboard reports independent observed states:

```text
Gateway                    ONLINE / UNAVAILABLE
Tenant                     AUTHENTICATED / NOT AUTHENTICATED
Proposal Agent             AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Protected Executor         AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Onboarding                 REGISTERED / NOT_REGISTERED / MISMATCH / UNAVAILABLE
Contract                   RESOLVED / UNAVAILABLE
Proposal Member grant      ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
Proposal Effective access  CONFIRMED / DENIED / UNKNOWN
Executor Member grant      ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
Executor Effective access  CONFIRMED / DENIED / UNKNOWN
```

`AUTHENTICATED` means a T3N principal session proved control of its credential and returned its canonical DID. `REGISTERED` means a public T3N Agent Card for the Proposal Agent DID was resolved and passed the closed card validation. Member grant state reflects the tenant delegation document and validity window. Effective access reflects `checkDelegation` performed through the authenticated delegated principal for the exact contract, canonical Tenant DID, functions and scopes.

Evaluation readiness requires Proposal Agent authentication, contract resolution, Proposal Member grant `ACTIVE` and Proposal Effective access `CONFIRMED`. Protected remediation readiness additionally requires Protected Executor authentication, Executor Member grant `ACTIVE` and Executor Effective access `CONFIRMED`. `DENIED` and `UNKNOWN` never produce a positive readiness state.

`RESOLVED` means contract id/version were resolved. It is not hardware attestation. Delegated functions/scopes/hosts and separately checked functions/scopes are exposed as sanitized technical status metadata.

## Policy and remediation exports

The Rust contract exports:

```text
evaluate-action
execute-remediation
verify-remediation
```

`evaluate-action` returns the exact policy version/hash used by the TEE. `execute-remediation` requires the approved version/hash and revalidates them against the current private KV policy before protected egress. It can return only the acceptance metadata needed for reconciliation. `verify-remediation` accepts a closed expected state and independently checks external operation/state data. A capability is rejected when its signed incident/action/decision/request/action/resource/purpose/fields/privateRefs/policyVersion/policyHash/Executor DID differ from the body/runtime identity, when expired or when its nonce was already consumed.

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

Generated artifacts are `docs/evidence/deployment-manifest.json` and `docs/evidence/testnet-run.json`. The orchestrator binds WASM SHA-256, canonical tenant/Proposal/Executor DIDs, contract id/version and policy version/hash. It provisions least-privilege Member grants, performs principal-side `checkDelegation` for Proposal and Executor, aborts unless both are effectively `ACTIVE`, and fails on mismatch, scenario `FAIL` or configured secret leakage. The deployment manifest also records the observed Agent Card registration state and, when a card is resolved, its public URI, SHA-256, verification time and service names. `NOT_RUN` is never counted as `PASS`.

`testnet-run.json` records a sanitized `delegation` object for Proposal Agent and Protected Executor containing only `memberState`, `effectiveState`, `checkedFunctions` and `checkedScopes`. It never persists the full Member Delegation document, SDK `satisfied`/`missing` payloads, private keys, API keys or tokens.

Agent Card metadata proves only what was observed during public resolution. `REGISTERED` means the resolved card matched the authenticated Proposal Agent DID and supported service schema; it does not prove Member grant, effective T3N access, policy authorization, TEE execution or hardware attestation.

For live remediation proof, both `SECURITY_API_URL` and `SECURITY_VERIFICATION_URL` must be configured/sealed and the Executor delegation includes only their derived HTTPS hosts. A live remediation scenario passes only on the documented execution plus independent verification sequence. An accepted 2xx without read-back cannot become a passing completion claim.

Profile-placeholder resolution must remain `NOT_RUN` in public evidence until a compatible T3N testnet profile/user context actually executes it. Local Rust/Java/gateway/frontend tests prove the closed-reference architecture but are not mislabeled as live profile-resolution evidence.

The submission capture harness rejects AI/T3N/operator/service/capability secrets in generated metadata and captures a remediation success only after the UI shows independently verified `COMPLETED`.

## Terminal 3 integration findings

The submission guide records the concrete `scopes` documentation inconsistency, the delegated `pii_did` authorization-subject requirement and the difference between Member Delegation read-back and effective `checkDelegation`. This project always sends explicit minimum scopes, derives `pii_did` from the authenticated tenant session and requires the delegated principal itself to perform the effective check.

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

Use `.env.example` only as a variable-name template. Never commit tenant keys, Proposal Agent keys, Protected Executor keys, AI provider keys, operator passwords, service tokens, capability keys, remediation credentials, private profile values or `.env` files.

The project will continue to be operated after the challenge. Future handover provisions new credentials instead of transferring existing private keys.

## Persistent T3N trust-manifest rollback protection

Before tenant, Proposal Agent or Protected Executor authentication, the gateway verifies the official signed T3N trust manifest and persists the accepted manifest version as a monotonic high-water mark per network. `T3N_TRUST_FLOOR_STORE_PATH` defaults to `/data/t3n-trust-floor.json`; the file contains only public trust metadata (`network`, accepted version and timestamp), never API keys, cookies or session credentials.

When a floor already exists, authentication calls `fetchTrustedManifest(network, { minVersion })`. A lower manifest is rejected, the floor is never silently decreased, and malformed or unreadable persisted state fails closed instead of resetting rollback history. Tenant, Proposal Agent and Protected Executor sessions receive the same `TrustManifestFloorStore` instance in each runtime, so they cannot establish independent floors for the same network. Atomic temp-file + fsync + rename persistence allows the accepted floor to survive process/container restart when `/data` is persistent.

Evidence uses precise wording: `Trust anchor VERIFIED` means the signed manifest established the T3N cluster trust boundary; `Rollback floor PERSISTED` means the version high-water mark was durably stored and reused across restarts. Neither claim is described as per-request hardware attestation.