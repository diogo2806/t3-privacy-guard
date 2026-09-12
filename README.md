# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

## What the demo proves

T3 Privacy Guard assumes the AI agent can be manipulated. A malicious proposal attempts to send protected credential data to `attacker.example`; the T3N policy contract returns `DENY`. The same incident can then produce a minimum legitimate revoke request. After an independent `ALLOW` and explicit authenticated operator authorization, the TEE executes the remediation using a credential stored only in the tenant private map.

The browser, Java backend and AI agent never receive the remediation credential value.

## Architecture

- `frontend/`: React + Vite dashboard served by Nginx.
- `backend/`: Java 21 + Spring Boot business API with durable incident orchestration and operator sessions.
- `t3n-gateway/`: Node.js + TypeScript adapter for `@terminal3/t3n-sdk` **5.2.0**.
- `contracts/privacy-guard/`: Rust/WIT policy and secretless-remediation contract compiled to WASI Preview 2 for T3N TEE execution.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; production deployment is expected to run services independently in containers.

```text
Browser / Nginx
      |
      | /api + operator session
      v
Spring Boot
      |
      | internal container network
      v
T3N Gateway
      |
      | authenticated tenant + agent sessions
      v
Terminal 3 / TEE / private KV
```

## Operator authentication

The public Nginx proxy exposes `/api`, so business APIs are protected by a Spring Security server-side operator session rather than by UI state alone.

Runtime-only variables:

- `OPERATOR_USERNAME`
- `OPERATOR_PASSWORD`
- `OPERATOR_SESSION_TIMEOUT`
- `SESSION_COOKIE_SECURE`

The operator identity is deliberately separate from T3N identities. T3N tenant/agent keys are never accepted by the login form.

Auth endpoints:

- `POST /api/auth/login`
- `GET /api/auth/session`
- `GET /api/auth/csrf`
- `POST /api/auth/logout`

Business APIs require role `OPERATOR`. Mutating requests use CSRF protection. Session cookies are HttpOnly and SameSite=Strict; production HTTPS deployments must set `SESSION_COOKIE_SECURE=true`.

## Dashboard and operational status

The React dashboard is composed from reusable components under `frontend/src/components`. CSS lives only under `frontend/src/shared/styles`, with `index.css` as the global entry.

The **Manual da Tela / Screen Manual** uses `BookOpen`, `aria-label`, `title` and an accessible dialog. It documents purpose, operator session, actions, fields, permissions, flow and states.

Operational status deliberately separates facts that are often conflated:

- **Gateway**: reachable or unavailable.
- **Tenant**: authenticated only when its T3N session is ready.
- **Agent**: authenticated only when its separate T3N session is ready.
- **Contract**: `RESOLVED` when canonical id/version can be resolved from T3N. This is not labelled hardware attestation.
- **Delegation**: `ACTIVE`, `REVOKED`, `NOT_GRANTED` or `UNKNOWN`, derived from the observed member grant.
- **Delegated functions / allowed hosts**: shown from the observed grant, never from a hardcoded “live” function list.

Demo flow:

1. Sign in as the application operator.
2. Confirm tenant, agent, contract and delegation states independently.
3. `Run attack scenario` and observe `DENY`.
4. `Prepare safe remediation` and observe `ALLOW` for the minimum request.
5. Record explicit human authorization.
6. Execute protected remediation.
7. Review sanitized audit history and evidence.

## Security baseline

- Never commit `T3N_API_KEY`, `T3N_AGENT_API_KEY`, remediation credentials, operator passwords or real `.env` files.
- Tenant and agent keys are separate credentials held only by the T3N gateway.
- Canonical tenant and agent DIDs come from authenticated T3N sessions (`did.value`).
- Operator authentication does not imply T3N authorization.
- Delegation scopes exact contract, functions, data and outbound hosts.
- `DENY`, `REDACT`, unavailable dependencies, malformed responses and ambiguous states fail closed.
- Java audit events contain sanitized operational metadata, never secret-bearing payloads.
- Java persists unique request ids and prior decisions/remediation results to prevent duplicate execution.
- The application never calls `UNKNOWN`, `REVOKED` or `NOT_GRANTED` a successful delegation.

## T3N identities and delegation

The gateway authenticates tenant and agent independently with SDK 5.2.0. `T3N_AGENT_API_KEY` must be a separate funded agent credential. Member delegation is written by the tenant/data-owner session with `updateMemberDelegation` and scopes access by contract, WIT functions, scopes, optional read scopes, outbound hosts and validity window.

Revocation expires only the matching agent+contract grant, preserving unrelated grants. Authentication alone never grants contract access.

For every delegated contract invocation, the agent remains the authenticated caller while `pii_did` is set internally from `tenantSession.getTenantDid()`. `pii_did` is never accepted from React, Java or user request payloads.

Identity/delegation endpoints:

- `GET /internal/t3n/status`
- `POST /internal/t3n/reconnect`
- `GET /internal/agent/status`
- `POST /internal/agent/connect`
- `POST /internal/agent/delegations`
- `GET /internal/agent/delegations/:contractId`
- `DELETE /internal/agent/delegations/:contractId`

## Terminal 3 integration findings

Two concrete findings shaped the integration:

1. **Member Delegation documentation sample omits a required field.** Current examples omit `scopes`, while the field reference marks `scopes` as required. T3 Privacy Guard requires and sends explicit scopes.
2. **Delegated-call target is easy to misconfigure.** The agent DID identifies the caller, while `pii_did` identifies whose grant/data authority is being used. T3 Privacy Guard derives it only from the authenticated tenant session.

The first is a documentation inconsistency. The second is an integration gotcha, not a platform-security bypass.

## TEE policy contract

`contracts/privacy-guard` implements the critical decision in Rust/WASM instead of trusting React, Java or the LLM.

Exports:

- `evaluate-action`: `ALLOW`, `REDACT` or `DENY`.
- `execute-remediation`: rechecks policy inside the TEE and performs protected egress only after an allowed decision.

The policy fails closed for malformed input, unknown actions, wrong purpose, invalid agent DID, direct secret disclosure and disallowed egress. `REDACT` identifies unnecessary non-secret fields without returning their values.

Replay requires durable state across calls. The WASM validates bounded `request_id`; Java makes `requestId` unique and reuses persisted policy/remediation results instead of executing twice.

### Build and register

```bash
rustup target add wasm32-wasip2
cd contracts/privacy-guard
cargo test
cargo build --target wasm32-wasip2 --release

cd ../../t3n-gateway
npm install
npm run contract:register
```

Registration uses the authenticated tenant through `TenantClient.contracts.register`. The canonical contract name is derived from the authenticated tenant DID. Runtime calls use the separately authenticated agent through `executeAndDecode` with canonical tenant `pii_did`.

Contract endpoints:

- `GET /internal/contracts/privacy-guard/identity`
- `POST /internal/contracts/privacy-guard/evaluate`
- `POST /internal/contracts/privacy-guard/remediate`

## Secretless remediation

1. Register contract version `0.2.0` and record the numeric T3N contract id.
2. Create private `z:<tid>:secrets` with readers/writers restricted to that contract id.
3. Seed `security_api_key` and `security_api_url` through the tenant control plane.
4. Delegate `execute-remediation` and only the required hostname.
5. The agent sends non-secret action metadata.
6. Inside the TEE, the contract re-evaluates policy, reads private KV and sends HTTPS via `http-with-placeholders`.
7. Only request id, completion status, HTTP code and optional operation id return to the application.

For a reproducible public demo, `SECURITY_API_URL=https://postman-echo.com/post` is supported as a synthetic adapter. Because echo services can reflect authorization headers, the contract never returns/logs the raw upstream body.

Setup after registration:

```bash
cd t3n-gateway
npm run contract:setup-remediation
```

## Backend incident orchestration

Spring Boot persists incidents, proposed actions, policy decisions, protected remediation results and audit events in an H2 file database under `/data`. A duplicate `requestId` is rejected. Persisted decisions/results are reused without invoking T3N/upstream twice.

A remediation requires all three layers:

```text
TEE decision ALLOW
      +
authenticated operator session
      +
explicit human authorization
      ↓
protected TEE execution
```

A previous `DENY` cannot be transformed into execution by Java.

## Adversarial evidence

The repository includes reproducible security controls instead of relying on screenshots/claims:

- Rust adversarial tests for policy abuse, exfiltration, purpose/host abuse, minimization and fail-closed behavior.
- Java tests for replay, idempotency, unavailable gateway, tampered responses and authorization gates.
- Gateway tests for delegation, revocation and canonical `pii_did` binding.
- A remediation regression test for reflected secret/header responses.
- An evidence leak detector for configured secrets/sentinels.
- `docs/evidence/scenario-matrix.md` maps controls to executable assertions.
- `npm run evidence:testnet` creates live T3N results only when actually executed. Unexecuted scenarios stay `NOT_RUN`.

```bash
bash scripts/run-local-evidence.sh

cd t3n-gateway
npm run evidence:testnet
```

See `docs/evidence/README.md` for live-test prerequisites and safety flags.

## Pinned toolchain

The repository pins direct Node dependencies and Docker image tags so a future install does not silently jump to a new direct framework/compiler version. This section records the declared toolchain; an evidence run is the source of truth for what has actually been executed successfully.

- Node build/runtime: `22.20.0-alpine3.22`
- React: `19.3.0`
- React DOM: `19.3.0`
- Vite: `8.2.2`
- `@vitejs/plugin-react`: `6.1.1`
- TypeScript: `5.9.2`
- Vitest: `2.1.8`
- T3N SDK: **`5.2.0`**
- Express: `5.1.0`
- Maven image: `3.9.16-eclipse-temurin-21`
- Java runtime image: `eclipse-temurin:21.0.12_8-jre`
- Nginx runtime: `1.27.5-alpine3.21-slim`
- Rust contract version: `0.2.0`, target `wasm32-wasip2`

Direct package versions are exact rather than `latest`/caret ranges. Transitive package resolution is recorded by the install environment when evidence is generated; this project does not treat an unexecuted dependency declaration as validation.

## Local builds

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm test && npm run typecheck && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

## Environment

Use `.env.example` only as a variable-name template. Inject all real secrets through the deployment environment. `DATABASE_URL` can override the backend H2 file database.
