# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

> **Judge / submission guide:** [`docs/submission/README.md`](docs/submission/README.md)  
> **Evidence reproduction:** [`docs/evidence/README.md`](docs/evidence/README.md)  
> **Adversarial matrix:** [`docs/evidence/scenario-matrix.md`](docs/evidence/scenario-matrix.md)

## What the demo proves

T3 Privacy Guard assumes the AI agent can be manipulated. The dashboard sends an actual textual prompt to a configured tool-calling model. The model can produce an unsafe structured proposal such as `host=attacker.example` plus `api_key`, but it cannot set a decision, identity, capability or secret. That proposal is persisted and evaluated independently by the T3N Rust/WASM policy, which returns `DENY`.

A legitimate model proposal can receive `ALLOW`, but `ALLOW` still does not execute anything. An authenticated operator must explicitly authorize remediation. Immediately before execution the Spring backend signs a short-lived, one-time capability bound to the exact persisted action, decision, fields and logical private-data references. The gateway validates service authentication, signature, expiry, payload equality and replay state before T3N execution.

Private profile values are structural to T3N. The agent, React, Spring Boot and gateway APIs carry only logical references such as `verified_email`; the Rust/WASM contract maps that closed reference to the supported T3N marker `{{profile.verified_contacts.email.value}}`, and T3N resolves the plaintext only during protected egress. The resolved value is never returned to the application. The remediation credential likewise remains outside browser, Spring Boot and AI-agent context.

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
                    v
        Rust maps verified_email
          to T3N profile marker
                    |
                    v
       protected egress resolves PII
```

- `frontend/`: React/Vite dashboard served by Nginx.
- `backend/`: Java 21/Spring Boot business API, operator sessions and durable business state.
- `t3n-gateway/`: isolated T3N SDK adapter, AI provider adapter, separate tenant/agent sessions and anti-replay protection.
- `contracts/privacy-guard/`: Rust/WIT policy, closed private-reference mapping and protected remediation contract for `wasm32-wasip2`.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; services are deployed independently in containers.

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

Unknown properties are rejected. In particular the model cannot supply `decision`, `allow`, `override`, `approved`, `agent_did`, `pii_did`, API keys, credentials, secrets, remediation capabilities or literal `{{profile...}}` markers. `agent_did` comes only from the authenticated Agent session and `pii_did` only from the authenticated tenant session.

The prompt is treated as untrusted content, not as an authorization source. Real private values must never be placed in demo prompts; the model asks only for an enumerated logical category when a supported private value is needed.

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

`PlaceholderDenied`, `PlaceholderUnknown` and `PlaceholderNoUserContext` fail closed. Upstream responses are reduced to status/operation metadata before leaving the contract, so an echoed private value is not returned to the application.

## Security boundaries

- Operator login is an application identity, not a T3N or AI-provider identity.
- `T3N_API_KEY`, `T3N_AGENT_API_KEY` and `AI_API_KEY` are gateway-only runtime secrets and are never returned to the browser.
- `GATEWAY_SERVICE_TOKEN` is a separate service-to-service credential.
- `REMEDIATION_CAPABILITY_KEY` signs one-time human authorization proofs and is distinct from every T3N/provider/remediation credential.
- Canonical tenant/agent DIDs come from authenticated T3N sessions.
- Delegated calls derive `pii_did` internally from the authenticated tenant session.
- Member delegation restricts contract, functions, scopes, hosts and validity.
- The model proposes; Rust/WASM policy decides. Provider failure, invalid tool output and T3N failure all fail closed.
- The model/application carry only logical private references; only the contract maps them to supported T3N profile markers.
- `ALLOW` + authenticated operator + explicit human authorization + valid one-time capability are required before protected remediation.
- Consumed capability nonces are persisted at `REMEDIATION_REPLAY_STORE_PATH` so replay protection survives gateway restart when `/data` is persistent.

See the threat model and claims matrix in [`docs/submission/README.md`](docs/submission/README.md).

## Operator authentication

Runtime names include:

```text
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
```

Business APIs require the Spring Security operator session and CSRF protection. The browser never receives T3N keys, AI provider keys, internal service token, remediation capability or resolved profile PII.

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

## Policy and remediation

The Rust contract exports `evaluate-action` and `execute-remediation`. The end-to-end path is:

```text
prompt -> real model -> structured proposal -> T3N policy
                                         DENY / REDACT / ALLOW
                                                           |
                                                   human authorization
                                                           |
                                                   signed one-time proof
                                                           |
                                                   protected execution
                                                           |
                                            T3N profile resolution at egress
```

A capability is rejected when its signed incident/action/decision/request/action/resource/purpose/fields/privateRefs differ from the body, when expired or when its nonce was already consumed.

## Evidence

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

Generated artifacts are `docs/evidence/deployment-manifest.json` and `docs/evidence/testnet-run.json`. The orchestrator binds WASM SHA-256, canonical DIDs and contract id/version and fails on mismatch, scenario `FAIL` or configured secret leakage. `NOT_RUN` is never counted as `PASS`.

Profile-placeholder resolution must remain `NOT_RUN` in public evidence until a compatible T3N testnet profile/user context actually executes it. Local Rust/Java/gateway/frontend tests prove the closed-reference architecture but are not mislabeled as live profile-resolution evidence.

The submission capture harness also rejects AI/T3N/operator/service/capability secrets in generated metadata.

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
- Rust contract: `0.2.0`, target `wasm32-wasip2`

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
