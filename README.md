# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

## Architecture

- `frontend/`: React + Vite, served by Nginx.
- `backend/`: Java 21 + Spring Boot with durable incident orchestration.
- `t3n-gateway/`: Node.js + TypeScript adapter for `@terminal3/t3n-sdk` 5.2.0.
- `contracts/privacy-guard/`: Rust/WIT TEE policy and remediation contract.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`.

## Security baseline

Tenant and agent use separate private keys held only by the gateway. Their DIDs come from authenticated T3N sessions. React and Java never receive those keys. Integration and validation failures fail closed. Audit events contain sanitized operational metadata only.

## T3N identity, delegation and contract

The gateway manages tenant/agent sessions and member delegation scoped by contract, functions, scopes, hosts and optional validity window. The `privacy-guard` contract exports `evaluate-action` and `execute-remediation`. Policy returns `ALLOW`, `REDACT` or `DENY`; duplicate `requestId` values are blocked durably by the Java database.

## Secretless remediation

The remediation path is intentionally different from a normal API integration:

1. register contract version `0.2.0` and record its numeric `contract_id`;
2. create private `z:<tid>:secrets` with readers/writers restricted to that numeric contract id;
3. seed `security_api_key` and `security_api_url` through the tenant control plane with `npm run contract:setup-remediation`;
4. grant the agent `execute-remediation` plus the destination in `allowed_hosts`;
5. the agent invokes the contract with only non-secret incident/action metadata;
6. inside the TEE, the contract re-evaluates policy, reads the credential through `kv-store`, and performs `http-with-placeholders` egress;
7. the contract returns only sanitized completion metadata (`status`, HTTP code, optional operation id), never the upstream body or credential.

For a reproducible public demo, `SECURITY_API_URL=https://postman-echo.com/post` is supported as a synthetic remediation adapter. Because echo services return request headers in their body, the contract deliberately never returns or logs the raw upstream payload. A production deployment should seed the real security API HTTPS endpoint and delegate only its hostname.

Terminal 3 additionally enforces the outbound hostname from the caller's member-delegation `allowed_hosts`; missing authorization causes host-level egress denial even if application code attempts the call.

### Setup

```bash
cd contracts/privacy-guard
cargo build --target wasm32-wasip2 --release

cd ../../t3n-gateway
npm run contract:register
# Set T3N_CONTRACT_NUMERIC_ID from registration output plus SECURITY_API_KEY/SECURITY_API_URL
npm run contract:setup-remediation
```

Never put `SECURITY_API_KEY` in Git, Java, React, an HTTP request body, or a Dockerfile.

## Business API

- `POST /api/incidents`
- `GET /api/incidents`
- `POST /api/incidents/{incidentId}/actions`
- `POST /api/incidents/{incidentId}/actions/{actionId}/evaluate`
- `POST /api/incidents/{incidentId}/actions/{actionId}/authorize-remediation`
- `POST /api/incidents/{incidentId}/actions/{actionId}/execute-remediation`
- `GET /api/incidents/{incidentId}/history`

A remediation must have a persisted `ALLOW`, then explicit authorization, before Java asks the gateway to execute. The TEE rechecks policy before egress, so Java cannot turn a prior `DENY` into a protected call.

## Build

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

Use `.env.example` only as a variable-name template. Inject all real secrets through the deployment environment.