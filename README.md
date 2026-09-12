# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

## What the demo proves

The product assumes the AI agent can be manipulated. A malicious proposal attempts to send protected credential data to `attacker.example`; the T3N contract returns `DENY`. The same incident can then produce a minimum legitimate revoke request to the delegated demo host; after an independent `ALLOW` and explicit business authorization, the TEE executes the remediation using a credential stored only in the tenant private map.

The browser, Java backend and agent never receive the credential value.

## Architecture

- `frontend/`: React + Vite dashboard served by Nginx.
- `backend/`: Java 21 + Spring Boot business API with durable incident orchestration.
- `t3n-gateway/`: Node.js + TypeScript adapter for `@terminal3/t3n-sdk` 5.2.0.
- `contracts/privacy-guard/`: Rust/WIT policy and secretless-remediation contract compiled to WASI Preview 2 for T3N TEE execution.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`.

## Dashboard

The React dashboard visualizes only real backend/gateway state. `GET /api/system/status` aggregates gateway health, authenticated tenant/agent state and the registered contract version; an unavailable capability is displayed as unavailable rather than as a successful attestation.

Demo flow:

1. `Run attack scenario` creates a critical incident and evaluates an exfiltration proposal against the registered T3N contract.
2. The expected result is `DENY`, with the policy reason visible beside the proposal.
3. `Prepare safe remediation` creates the minimum legitimate revoke request and evaluates it separately.
4. An `ALLOW` enables `Authorize remediation`; authorization still does not execute anything.
5. `Execute protected remediation` invokes the TEE function, which rechecks policy, reads the credential from private KV and performs delegated egress.
6. The sanitized audit trail records the business flow without recording the secret.

The Screen Manual is available from the `BookOpen` button in the header and documents purpose, data, actions, rules, permissions, flow and all decision/error states. UI components live exclusively in `frontend/src/components`. All CSS lives under `frontend/src/shared/styles`, with `index.css` as the only global entry point.

## Security baseline

- Never commit T3N keys, remediation credentials, or real `.env` files.
- Tenant and agent keys are separate and held only by the gateway.
- React and Java never receive T3N private keys or the remediation credential.
- Tenant and agent DIDs come from authenticated T3N sessions.
- Authentication does not imply authorization; delegation scopes contract, functions, data and outbound hosts.
- `DENY`, `REDACT`, unavailable dependencies and invalid responses fail closed.
- Java persists unique request ids and prior decisions/remediation results to prevent duplicate execution.

## TEE contract and secretless remediation

The contract exports `evaluate-action` and `execute-remediation`. It returns `ALLOW`, `REDACT` or `DENY`, and re-evaluates the action immediately before protected egress. Private map `z:<tid>:secrets` is restricted to the numeric contract id. `security_api_key` and `security_api_url` are seeded through the tenant control plane; the contract reads them through `kv-store` and sends HTTPS through `http-with-placeholders`, still subject to T3N `allowed_hosts`.

For a reproducible public demo, `https://postman-echo.com/post` can be used as the synthetic remediation endpoint. The raw echo response is never returned or logged, preventing reflected authorization headers from becoming a leak.

## API surface

Business API:

- `GET /api/system/status`
- `POST /api/incidents`
- `GET /api/incidents`
- `GET /api/incidents/{incidentId}`
- `POST /api/incidents/{incidentId}/actions`
- `GET /api/incidents/{incidentId}/actions`
- `POST /api/incidents/{incidentId}/actions/{actionId}/evaluate`
- `GET /api/incidents/{incidentId}/actions/{actionId}/decision`
- `POST /api/incidents/{incidentId}/actions/{actionId}/authorize-remediation`
- `POST /api/incidents/{incidentId}/actions/{actionId}/execute-remediation`
- `GET /api/incidents/{incidentId}/history`

Gateway operations remain internal to the backend/container network.

## Build

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm test && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

Use `.env.example` only as a variable-name template. Inject all real secrets through the deployment environment.