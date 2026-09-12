# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

> **Judge / submission guide:** [`docs/submission/README.md`](docs/submission/README.md)  
> **Evidence reproduction:** [`docs/evidence/README.md`](docs/evidence/README.md)  
> **Adversarial matrix:** [`docs/evidence/scenario-matrix.md`](docs/evidence/scenario-matrix.md)

## What the demo proves

T3 Privacy Guard assumes the AI agent can be manipulated. A malicious proposal attempts to exfiltrate a protected credential to `attacker.example`; the Rust/WASM policy returns `DENY`. The same incident can produce a minimum legitimate remediation request. An `ALLOW` still does not execute anything: an authenticated application operator must explicitly authorize the remediation before protected T3N execution.

Human authorization is enforced end-to-end. Immediately before execution the Spring backend signs a short-lived, one-time capability bound to the incident, action, persisted ALLOW decision, request, purpose, resource and exact field set. The T3N gateway requires both service-to-service authentication and that capability, verifies its HMAC, rejects expiry/body mismatch and persists consumed nonces to reject replay. The capability never reaches the browser.

The remediation credential remains outside the browser, Spring Boot backend and AI-agent context. It is consumed through the private T3N contract path.

## Architecture

```text
React / Nginx
     |
     | operator session + /api
     v
Java 21 / Spring Boot
     |
     | service auth + one-time signed remediation capability
     v
Node / TypeScript T3N Gateway
     |
     | @terminal3/t3n-sdk 5.2.0
     v
T3N / Rust WASM / private KV
```

- `frontend/`: React/Vite dashboard served by Nginx.
- `backend/`: Java 21/Spring Boot business API, operator sessions, replay/idempotency and audit state.
- `t3n-gateway/`: isolated T3N SDK adapter with separate tenant/agent sessions and a durable anti-replay store for privileged capabilities.
- `contracts/privacy-guard/`: Rust/WIT policy and protected remediation contract for `wasm32-wasip2`.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; services can be deployed independently in containers.

## Security boundaries

- Operator login is an application identity, not a T3N identity.
- `T3N_API_KEY` and `T3N_AGENT_API_KEY` are separate and gateway-only.
- `GATEWAY_SERVICE_TOKEN` is a distinct service-to-service credential; it is never reused as a T3N key or operator password.
- `REMEDIATION_CAPABILITY_KEY` signs one-time human authorization proofs and is distinct from every T3N/remediation credential.
- Canonical tenant/agent DIDs come from authenticated T3N sessions.
- Delegated calls derive `pii_did` internally from the authenticated tenant session.
- Member delegation restricts contract, functions, scopes, hosts and validity.
- `DENY`, `REDACT`, malformed responses, unavailable policy evaluation and ambiguous states fail closed.
- Java persists unique request ids and prior results to prevent duplicate business execution.
- `ALLOW` + authenticated operator + explicit human authorization + valid one-time capability are all required before remediation execution.
- Privileged delegation/connect routes require internal service authentication.
- Consumed capability nonces are persisted at `REMEDIATION_REPLAY_STORE_PATH`; mount the gateway `/data` volume persistently so replay protection survives container restarts.
- `UNKNOWN`, `REVOKED` and `NOT_GRANTED` are never displayed as successful delegation.

See the threat model and claims matrix in [`docs/submission/README.md`](docs/submission/README.md).

## Operator authentication

Required runtime variables:

```text
OPERATOR_USERNAME
OPERATOR_PASSWORD
OPERATOR_SESSION_TIMEOUT
SESSION_COOKIE_SECURE
GATEWAY_SERVICE_TOKEN
REMEDIATION_CAPABILITY_KEY
REMEDIATION_CAPABILITY_TTL_SECONDS
REMEDIATION_REPLAY_STORE_PATH
```

Business APIs require the Spring Security operator session. Mutating requests require CSRF protection. The browser never receives a T3N private key, internal service token or remediation capability.

## T3N operational status

The dashboard reports independent observed states:

```text
Gateway       ONLINE / UNAVAILABLE
Tenant        AUTHENTICATED / NOT AUTHENTICATED
Agent         AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Contract      RESOLVED / UNAVAILABLE
Delegation    ACTIVE / REVOKED / NOT_GRANTED / UNKNOWN
```

`RESOLVED` means contract id/version were resolved. It is not labelled hardware attestation. Delegated functions and allowed hosts come from the observed grant, not from a hardcoded live-function list.

## Policy and remediation

The Rust contract exports:

- `evaluate-action`: `ALLOW`, `REDACT` or `DENY`;
- `execute-remediation`: rechecks policy and performs protected egress only when the request remains allowed.

The authorization path is:

```text
unsafe proposal -> T3N DENY
safe proposal   -> T3N ALLOW
                     |
             human authorization
                     |
             signed one-time proof
                     |
          gateway verifies + consumes nonce
                     |
             protected T3N execution
```

A capability is never accepted when its signed incident/action/decision/request/action/resource/purpose/fields differ from the request body, when it is expired, or when the nonce was already consumed.

## Evidence

Local controls:

```bash
bash scripts/run-local-evidence.sh
```

One-command live testnet evidence, after configuring valid rotated credentials/credits and building the WASM:

```bash
cd t3n-gateway
npm install
npm run evidence:live
```

Generated live artifacts:

```text
docs/evidence/deployment-manifest.json
docs/evidence/testnet-run.json
```

The orchestrator binds the WASM SHA-256, canonical DIDs and contract id/version to the testnet evidence. It fails on identity/version/hash mismatch, scenario `FAIL` or configured secret leakage. Optional scenarios that did not execute remain `NOT_RUN`, never `PASS`.

The dashboard **Evidence** view is read-only and returns only an allowlisted projection of consistent live evidence through the authenticated backend.

## Terminal 3 integration findings

Two concrete findings are documented with impact/workaround in [`docs/submission/README.md`](docs/submission/README.md):

1. Member Delegation examples omit `scopes` although the field reference treats it as required.
2. Delegated calls can use the wrong authorization subject if `pii_did` is omitted; this project always derives it from the authenticated tenant session.

## Pinned toolchain

Direct dependencies and Docker tags are explicit rather than `latest`/caret ranges:

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
- Rust contract: `0.2.0`, target `wasm32-wasip2`

Declared versions are not presented as execution proof; generated evidence is the source of truth for what actually ran.

## Local builds

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm test && npm run typecheck && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

## Environment

Use `.env.example` only as a variable-name template. Never commit real tenant keys, agent keys, operator passwords, service tokens, capability signing keys, remediation credentials or `.env` files.

The project will continue to be operated after the challenge. A future handover process that rotates/provisions new credentials is documented in the submission guide; existing private keys are not transferred through GitHub or the UI.
