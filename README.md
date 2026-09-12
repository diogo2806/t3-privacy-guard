# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

## Architecture

- `frontend/`: React + Vite, production build served by Nginx.
- `backend/`: Java 21 + Spring Boot business API.
- `t3n-gateway/`: Node.js + TypeScript adapter for `@terminal3/t3n-sdk` 5.2.0.
- `contracts/privacy-guard/`: Rust contract compiled to WebAssembly for T3N TEE execution.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; production deployment is expected to run the services independently in containers.

## Security baseline

- Never commit `T3N_API_KEY`, `T3N_AGENT_API_KEY`, external service secrets, or real `.env` files.
- Tenant and agent keys must be different credentials.
- The React bundle never receives T3N credentials.
- The Java backend does not need either T3N private key.
- Canonical tenant and agent DIDs come from authenticated T3N sessions (`did.value`), never from hardcoded configuration.

## T3N identities and delegation

The gateway authenticates the tenant and the agent independently using the SDK 5.2.0 handshake/auth flow. Set `T3N_AGENT_API_KEY` to a separate key claimed/funded for the agent. When absent, tenant connectivity still works but agent status remains `configured: false`.

Member delegation is performed through the tenant/data-owner session with `updateMemberDelegation`, scoped by:

- exact `contract_id`;
- allowed WIT `functions`;
- exact data `scopes`;
- optional `read_scopes`;
- optional `allowed_hosts`;
- optional validity window.

Revocation updates only the matching agent+contract grant with an already-expired validity window, so the agent loses authority without replacing or deleting unrelated grants in the member delegation document.

Internal endpoints:

- `GET /internal/t3n/status`
- `POST /internal/t3n/reconnect`
- `GET /internal/agent/status`
- `POST /internal/agent/connect`
- `POST /internal/agent/delegations`
- `GET /internal/agent/delegations/:contractId`
- `DELETE /internal/agent/delegations/:contractId`

The agent DID is always read from its own authenticated session. Authentication alone does not grant contract access.

## Local builds

### Frontend

```bash
cd frontend
npm install
npm run build
```

### Backend

```bash
cd backend
mvn test
mvn package
```

### T3N gateway

```bash
cd t3n-gateway
npm install
npm test
npm run typecheck
npm run build
```

### TEE contract

```bash
rustup target add wasm32-wasip2
cd contracts/privacy-guard
cargo build --target wasm32-wasip2 --release
```

## Environment

Use `.env.example` only as a list of variable names. Inject real secrets through the deployment environment. T3N keys belong only to the T3N gateway container.
