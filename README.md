# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

## Architecture

- `frontend/`: React + Vite, production build served by Nginx.
- `backend/`: Java 21 + Spring Boot business API with durable incident orchestration.
- `t3n-gateway/`: Node.js + TypeScript adapter for `@terminal3/t3n-sdk` 5.2.0.
- `contracts/privacy-guard/`: Rust/WIT policy contract compiled to a WASI Preview 2 component for T3N TEE execution.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; production deployment is expected to run the services independently in containers.

## Security baseline

- Never commit `T3N_API_KEY`, `T3N_AGENT_API_KEY`, external service secrets, or real `.env` files.
- Tenant and agent keys must be different credentials and exist only in the gateway container.
- The React bundle and Java backend never receive T3N private keys.
- Canonical tenant and agent DIDs come from authenticated T3N sessions (`did.value`).
- Authorization, integration or validation failure fails closed.
- Java audit events store sanitized operational metadata, never secret-bearing payloads.

## T3N identities and delegation

The gateway authenticates tenant and agent independently using the SDK 5.2.0 handshake/auth flow. `T3N_AGENT_API_KEY` is a separate funded agent credential. Member delegation is written by the tenant/data-owner session with `updateMemberDelegation` and can scope:

- exact `contract_id`;
- WIT `functions`;
- data `scopes`;
- optional `read_scopes`;
- optional `allowed_hosts`;
- optional validity window.

Revocation expires only the matching agent+contract grant, preserving unrelated grants.

Identity/delegation endpoints:

- `GET /internal/t3n/status`
- `POST /internal/t3n/reconnect`
- `GET /internal/agent/status`
- `POST /internal/agent/connect`
- `POST /internal/agent/delegations`
- `GET /internal/agent/delegations/:contractId`
- `DELETE /internal/agent/delegations/:contractId`

Authentication alone does not grant contract access.

## TEE policy contract

`contracts/privacy-guard` implements the critical decision inside Rust/WASM, not in React, Java or the LLM. Its WIT world follows Terminal 3's `generic-input` envelope and exports `evaluate-action`.

The result is exactly one of:

- `ALLOW`: action and requested fields fit the minimum policy scope;
- `REDACT`: action can proceed only after unnecessary non-secret fields are removed;
- `DENY`: action, purpose, host, identity or secret request violates policy.

The policy fails closed for malformed input, unknown action, wrong purpose, invalid agent DID, direct secret disclosure and disallowed egress. Replay requires durable cross-call state, so the WASM validates a bounded `request_id` while durable duplicate prevention is performed by the Java orchestration layer.

Build and register:

```bash
rustup target add wasm32-wasip2
cd contracts/privacy-guard
cargo test
cargo build --target wasm32-wasip2 --release

cd ../../t3n-gateway
npm install
npm run contract:register
```

Registration uses the authenticated `TenantClient` and `tenant.contracts.register({ tail, version, wasm })`. The canonical name is computed as `z:<tid>:<tail>` from the authenticated tenant DID. Runtime evaluation uses the separately authenticated agent and `executeAndDecode`.

Contract endpoints:

- `GET /internal/contracts/privacy-guard/identity`
- `POST /internal/contracts/privacy-guard/evaluate`

## Backend incident orchestration

The Spring Boot API persists incidents, proposed actions, policy decisions and audit events in an H2 file database under `/data`. `requestId` is unique in the database. A duplicate request is rejected with HTTP 409, and an already persisted policy decision is returned without invoking T3N again. This is the durable idempotency/replay boundary for the stateless policy contract.

Business endpoints:

- `POST /api/incidents`
- `GET /api/incidents`
- `GET /api/incidents/{incidentId}`
- `POST /api/incidents/{incidentId}/actions`
- `GET /api/incidents/{incidentId}/actions`
- `POST /api/incidents/{incidentId}/actions/{actionId}/evaluate`
- `POST /api/incidents/{incidentId}/actions/{actionId}/authorize-remediation`
- `GET /api/incidents/{incidentId}/history`

The backend calls only the gateway's internal policy API and never receives a T3N key. `DENY`, `REDACT`, timeout, malformed response or unavailable gateway never authorize remediation. A typed frontend consumer exists in `frontend/src/services/privacyGuardApi.ts` for the dashboard layer.

## Local builds

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

## Environment

Use `.env.example` only as a variable-name template. Inject real secrets through the deployment environment. `DATABASE_URL` can override the default H2 file database for the backend.