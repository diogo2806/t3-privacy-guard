# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

## Architecture

- `frontend/`: React + Vite, production build served by Nginx.
- `backend/`: Java 21 + Spring Boot business API and durable incident orchestration.
- `t3n-gateway/`: Node.js + TypeScript adapter for `@terminal3/t3n-sdk` 5.2.0.
- `contracts/privacy-guard/`: Rust/WIT policy contract compiled to a WASI Preview 2 component for T3N TEE execution.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; production deployment is expected to run the services independently in containers.

## Security baseline

- Never commit T3N private keys, external service secrets, or real `.env` files.
- Tenant and agent keys are separate and exist only in the gateway container.
- Canonical DIDs come from authenticated T3N sessions.
- Policy failure, integration failure or malformed input fails closed.
- The Java audit trail stores operational metadata, not full secret-bearing payloads.

## Backend incident flow

The Spring Boot API persists incidents, proposed actions, policy decisions and audit events in an H2 file database under `/data`. `requestId` is unique and persisted: duplicate proposals are rejected with HTTP 409, and an already-persisted decision is returned without calling T3N again. This is the durable replay/idempotency boundary for the pure policy contract.

Core endpoints:

- `POST /api/incidents`
- `GET /api/incidents`
- `GET /api/incidents/{incidentId}`
- `POST /api/incidents/{incidentId}/actions`
- `GET /api/incidents/{incidentId}/actions`
- `POST /api/incidents/{incidentId}/actions/{actionId}/evaluate`
- `POST /api/incidents/{incidentId}/actions/{actionId}/authorize-remediation`
- `GET /api/incidents/{incidentId}/history`

The backend calls only the internal gateway evaluation API. It does not receive `T3N_API_KEY` or `T3N_AGENT_API_KEY`. A `DENY`, `REDACT`, timeout or unavailable gateway never authorizes remediation. The frontend already has a typed consumer in `frontend/src/services/privacyGuardApi.ts`; the full dashboard is delivered by the dedicated frontend issue.

## T3N identities, delegation and TEE contract

The gateway independently authenticates tenant and agent, obtains each DID from `did.value`, and manages member delegation scoped by contract, functions, scopes, optional read scopes, hosts and validity window. The Rust/WIT `evaluate-action` contract returns `ALLOW`, `REDACT` or `DENY` and is registered through `TenantClient.contracts.register` and invoked by the agent through `executeAndDecode`.

## Build

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

## Environment

Use `.env.example` only as a variable-name template. Inject real secrets through the deployment environment. `DATABASE_URL` can override the default H2 file database for backend deployment.