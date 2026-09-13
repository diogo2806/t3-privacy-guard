# T3 Privacy Guard

**Enterprise trust runtime for AI agents on the Terminal 3 Network.**

T3 Privacy Guard is designed for a simple enterprise assumption: **the AI model can be useful and still be untrusted**. The model may analyze an incident and propose an action, but it is not allowed to become the authority that decides policy, selects trusted identities, retrieves private profile values directly, or declares a critical side effect completed.

The product separates those responsibilities across independent controls:

```text
Untrusted AI
    |
    | proposes
    v
T3N policy / Rust WASM
    |
    | DENY / REDACT / ALLOW
    v
Human authorization
    |
    | approves business intent
    v
One-time execution capability
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
T3N policy -> ALLOW
   |
   v
Authenticated human authorizes
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

This is why `ALLOW` is not the same thing as execution and why HTTP `2xx` is not the same thing as completion.

## What the demo proves

T3 Privacy Guard assumes the AI agent can be manipulated. The dashboard sends an actual textual prompt to a configured tool-calling model. The model can produce an unsafe structured proposal such as `host=attacker.example` plus `api_key`, but it cannot set a decision, identity, capability or secret. That proposal is persisted and evaluated independently by the T3N Rust/WASM policy, which returns `DENY`.

A legitimate model proposal can receive `ALLOW`, but `ALLOW` still does not execute anything. An authenticated operator must explicitly authorize remediation. Immediately before execution the Spring backend signs a short-lived, one-time capability bound to the exact persisted action, decision, fields, logical private-data references and the exact policy version/hash that produced the decision. The gateway validates service authentication, signature, expiry, payload equality, policy provenance and replay state before T3N execution.

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
      | authenticated Agent DID + tenant pii_did
      v
T3N / Rust WASM policy
   DENY | REDACT | ALLOW
                    |
              human authorization
                    |
              one-time capability
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
- `t3n-gateway/`: isolated T3N SDK adapter, AI provider adapter, separate tenant/agent sessions, versioned policy provisioning, persistent T3N trust rollback protection and anti-replay protection.
- `contracts/privacy-guard/`: Rust/WIT policy, closed private-reference mapping, protected remediation and independent verification for `wasm32-wasip2`.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; services are deployed independently in containers.

## Authority separation

The architecture deliberately prevents the model from owning security authority.

| Responsibility | Authority |
|---|---|
| Understand prompt and propose an action | AI model |
| Authenticate tenant and agent identity | T3N sessions with verified signed trust manifest and persisted rollback floor |
| Supply versioned operational rules | Private T3N KV policy map |
| Enforce immutable security invariants and decide allowed action/data/host | Rust/WASM contract |
| Approve business remediation | Authenticated operator |
| Prove an exact approved execution | Short-lived one-time capability |
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

`AI_PROVIDER=disabled` is the safe default. When disabled or unavailable, agent analysis fails closed; no fixture is promoted as live AI. Remote provider URLs require HTTPS; plain HTTP is accepted only for explicit loopback development endpoints.

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

Unknown properties are rejected. In particular the model cannot supply `decision`, `allow`, `override`, `approved`, `agent_did`, `pii_did`, API keys, credentials, secrets, remediation capabilities, policy documents or literal `{{profile...}}` markers. `agent_did` comes only from the authenticated Agent session and `pii_did` only from the authenticated tenant session.

Real private values must never be placed in demo prompts; the model asks only for an enumerated logical category when a supported private value is needed.

## Current policy vocabulary

The default operational policy contains four concrete security actions:

| Action | Purpose | Minimum normal fields | Private reference |
|---|---|---|---|
| `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none |
| `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none |
| `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none |
| `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `verified_email` allowed |

Extra non-secret fields are minimized with `REDACT`. Forbidden secret fields are denied. Unsupported actions, purposes, hosts or private references fail closed.

## Versioned operational policy in T3N KV

Operational rules are no longer compiled as the source of truth for every host/field/purpose change. Contract `0.4.0` loads the active canonical JSON policy from the private tenant map `privacy-guard-policy`, key `current`, inside the TEE. Each decision returns `policy_version`, deterministic canonical SHA-256 `policy_hash` and the action's human-authorization requirement. Spring persists this metadata and protected remediation is bound to the exact approved version/hash; if the active policy changes after authorization, execution is rejected and must be evaluated again.

The external policy may configure only:

- enabled actions;
- purpose per action;
- allowed destination hosts;
- allowed normal field names;
- supported logical private references from the contract vocabulary;
- whether host egress is required;
- whether explicit human authorization is required.

Security invariants remain compiled in Rust/WASM and cannot be weakened by KV configuration: input/schema bounds, fail-closed behavior, safe normalization, host validation, T3N identity boundaries, rejection of client-supplied policy authority, the closed private-reference vocabulary and `FORBIDDEN_SECRET_FIELDS` such as `api_key`, tokens, passwords and private keys.

Provision or update the policy explicitly:

```bash
cd t3n-gateway
npm run contract:setup-policy
```

`T3N_POLICY_FILE` selects the local source document. Publishing writes an immutable snapshot under `version:<policyVersion>`, verifies the read-back hash/version, moves `current`, and records a change-history entry. Reusing the same version with different canonical content is rejected; publish a new version instead.

Rollback is explicit and can target only an already persisted immutable snapshot:

```bash
T3N_POLICY_ROLLBACK_VERSION=2026-09-12.1 npm run contract:setup-policy
```

The rollback verifies the stored snapshot, updates `current`, verifies read-back and records the previous/target version and hashes in T3N KV history. `policyVersion`/`policyHash` are provenance metadata. They identify exactly which policy produced a decision or evidence run; they are not hardware attestation.

## Persistent T3N trust-manifest rollback protection

Before tenant or agent authentication, the gateway verifies the official signed T3N trust manifest and persists the accepted manifest version as a monotonic high-water mark per network. `T3N_TRUST_FLOOR_STORE_PATH` defaults to `/data/t3n-trust-floor.json`; the file contains only public trust metadata (`network`, accepted version and timestamp), never API keys, cookies or session credentials.

When a floor already exists, authentication requests a manifest at least as new as that floor. A lower manifest is rejected, the floor is never silently decreased, and malformed or unreadable persisted state fails closed instead of resetting rollback history. Tenant and Agent sessions share the same `TrustManifestFloorStore` instance in each runtime so they cannot establish independent floors for the same network. Atomic persistence allows the accepted floor to survive process/container restart when `/data` is persistent.

Evidence uses precise wording: `Trust anchor VERIFIED` means the signed manifest established the T3N cluster trust boundary; `Rollback floor PERSISTED` means the version high-water mark was durably stored and reused across restarts. Neither claim is described as per-request hardware attestation.

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
- `T3N_API_KEY`, `T3N_AGENT_API_KEY` and `AI_API_KEY` are gateway-only runtime secrets and are never returned to the browser.
- `GATEWAY_SERVICE_TOKEN` is a separate service-to-service credential and protects internal gateway calls, including policy evaluation.
- `REMEDIATION_CAPABILITY_KEY` signs one-time human authorization proofs and is distinct from every T3N/provider/remediation credential.
- Canonical tenant/agent DIDs come from authenticated T3N sessions after trust-manifest verification and rollback-floor enforcement.
- Delegated calls derive `pii_did` internally from the authenticated tenant session.
- Member delegation restricts contract, functions, scopes, hosts and validity.
- The model proposes; Rust/WASM policy decides. Provider failure, invalid tool output, missing/corrupt policy, T3N trust failure and T3N execution failure all fail closed.
- The model/application carry only logical private references; only the contract maps them to supported T3N profile markers.
- The external operational policy cannot override compiled secret prohibitions, identity/delegation rules or safe host validation.
- `ALLOW` + authenticated operator + explicit human authorization when required + valid one-time capability are required before protected remediation.
- Consumed capability nonces are persisted at `REMEDIATION_REPLAY_STORE_PATH` so replay protection survives gateway restart when `/data` is persistent.
- The accepted T3N trust-manifest floor is persisted at `T3N_TRUST_FLOOR_STORE_PATH` and never silently decreased.

See the threat model and claims matrix in [`docs/submission/README.md`](docs/submission/README.md).

## Runtime configuration

Relevant names include:

```text
T3N_CONTRACT_VERSION
T3N_CONTRACT_NUMERIC_ID
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

`T3N_POLICY_ROLLBACK_VERSION` is an explicit one-shot operator input to `contract:setup-policy`, not a normal long-lived application setting. `SECURITY_API_URL` is the protected action endpoint. `SECURITY_VERIFICATION_URL` is the independent read-back endpoint. Both remediation endpoints are seeded into the T3N private map by the setup script; the verification endpoint is not a browser/backend credential.

Business APIs require the Spring Security operator session and CSRF protection. Internal Spring-to-gateway calls require `GATEWAY_SERVICE_TOKEN`. The browser never receives T3N keys, AI provider keys, internal service token, remediation capability, remediation credential or resolved profile PII.

## T3N operational status

The dashboard reports independent observed states:

```text
Gateway       ONLINE / UNAVAILABLE
Tenant        AUTHENTICATED / NOT AUTHENTICATED
Agent         AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Contract      RESOLVED / UNAVAILABLE
Delegation    ACTIVE / REVOKED / NOT_GRANTED / UNKNOWN
```

`RESOLVED` means contract id/version were resolved. It is not hardware attestation. Delegated functions and allowed hosts come from the observed grant.

## Policy and remediation exports

The Rust contract exports:

```text
evaluate-action
execute-remediation
verify-remediation
```

`evaluate-action` reads the versioned T3N KV policy inside the contract and fails closed when the policy is missing or invalid. `execute-remediation` re-reads the active policy and rejects execution when its canonical version/hash differs from the authorization-bound metadata. It can return only the acceptance metadata needed for reconciliation. `verify-remediation` accepts a closed expected state and independently checks external operation/state data. A capability is rejected when its signed incident/action/decision/request/action/resource/purpose/fields/privateRefs/policyVersion/policyHash differ from the body, when expired or when its nonce was already consumed.

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

Generated artifacts are `docs/evidence/deployment-manifest.json` and `docs/evidence/testnet-run.json`. The orchestrator binds WASM SHA-256, canonical DIDs, contract id/version, the provisioned operational `policyVersion`/`policyHash`, verified T3N trust anchor and persisted rollback floor; it fails on mismatch, scenario `FAIL` or configured secret leakage. `NOT_RUN` is never counted as `PASS`.

For live remediation proof, both `SECURITY_API_URL` and `SECURITY_VERIFICATION_URL` must be configured/sealed and the delegation includes only their derived HTTPS hosts. A live remediation scenario passes only on the documented execution plus independent verification sequence. An accepted 2xx without read-back cannot become a passing completion claim.

Profile-placeholder resolution must remain `NOT_RUN` in public evidence until a compatible T3N testnet profile/user context actually executes it. Local Rust/Java/gateway/frontend tests prove the closed-reference architecture but are not mislabeled as live profile-resolution evidence.

The submission capture harness rejects AI/T3N/operator/service/capability secrets in generated metadata and captures a remediation success only after the UI shows independently verified `COMPLETED`.

## Terminal 3 integration findings

The submission guide records the concrete `scopes` documentation inconsistency and the delegated `pii_did` authorization-subject gotcha. This project always sends explicit scopes and derives `pii_did` from the authenticated tenant session.

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

Use `.env.example` only as a variable-name template. Never commit tenant keys, agent keys, AI provider keys, operator passwords, service tokens, capability keys, remediation credentials, private profile values or `.env` files.

The project will continue to be operated after the challenge. Future handover provisions new credentials instead of transferring existing private keys.
