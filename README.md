# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

## Architecture

- `frontend/`: React + Vite, production build served by Nginx.
- `backend/`: Java 21 + Spring Boot business API.
- `t3n-gateway/`: Node.js + TypeScript adapter for `@terminal3/t3n-sdk` 5.2.0.
- `contracts/privacy-guard/`: Rust/WIT policy contract compiled to a WASI Preview 2 component for T3N TEE execution.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`.

## Security model

Tenant and agent authenticate with different keys and receive their canonical DIDs from their own T3N sessions. Authorization is a separate member-delegation grant. The policy decision itself is implemented in the Rust/WASM contract rather than trusted to React, Java or the LLM.

The `evaluate-action` contract produces exactly one of:

- `ALLOW`: action and data are inside the minimum policy scope;
- `REDACT`: action is allowed only after unnecessary non-secret fields are removed;
- `DENY`: action, purpose, destination or requested secret is forbidden.

The contract fails closed for malformed input, unknown actions, wrong purposes, invalid agent DIDs, direct secret disclosure and hosts outside its policy. T3N member delegation remains the independent platform-level restriction for which agent, contract functions, scopes and egress hosts are callable.

Replay protection requires durable state outside this pure policy function and is enforced at the orchestration/idempotency layer rather than falsely represented as a stateless WASM guarantee.

## Contract build, registration and invocation

```bash
rustup target add wasm32-wasip2
cd contracts/privacy-guard
cargo test
cargo build --target wasm32-wasip2 --release
```

The contract follows the Terminal 3 WIT envelope (`generic-input`) and exports one operation: `evaluate-action`.

Register it from `t3n-gateway` after building:

```bash
npm install
npm run contract:register
```

Registration uses the authenticated tenant DID, `TenantClient`, `tenant.contracts.register({ tail, version, wasm })`, `T3N_CONTRACT_TAIL` and `T3N_CONTRACT_VERSION`. The gateway computes the canonical `z:<tid>:<tail>` identity from the authenticated tenant DID.

Runtime evaluation is performed by the separately authenticated agent through `executeAndDecode`, never by a browser-side SDK call:

- `GET /internal/contracts/privacy-guard/identity`
- `POST /internal/contracts/privacy-guard/evaluate`

The agent still requires a matching member delegation grant for `evaluate-action`.

## Environment

Use `.env.example` only as a list of variable names. Inject real secrets through the deployment environment. T3N private keys belong only to the T3N gateway container and are never returned by its APIs.
