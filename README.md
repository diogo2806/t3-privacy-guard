# T3 Privacy Guard

Confidential Incident Response Agent for the Terminal 3 Network challenge.

## Architecture

- `frontend/`: React + Vite, production build served by Nginx.
- `backend/`: Java 21 + Spring Boot business API.
- `t3n-gateway/`: Node.js + TypeScript adapter for `@terminal3/t3n-sdk` 5.2.0.
- `contracts/privacy-guard/`: Rust contract compiled to WebAssembly for T3N TEE execution.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; production deployment is expected to run the services independently in containers.

## Security baseline

- Never commit `T3N_API_KEY`, agent private keys, external service secrets, or real `.env` files.
- The React bundle never receives T3N credentials.
- The Java backend does not need the T3N private key.
- Canonical DIDs come from the authenticated T3N session (`did.value`), never from hardcoded configuration.

## T3N gateway authentication

The gateway follows the Terminal 3 ADK 5.2.0 Quickstart sequence server-side:

1. `setEnvironment(T3N_NETWORK)` selects `testnet` or `production`.
2. `loadWasmComponent()` loads the SDK cryptographic component.
3. `fetchTrustedManifest(network)` provides the mandatory hosted-node trust anchor.
4. `T3nClient.handshake()` establishes the trusted connection.
5. `authenticate(createEthAuthInput(address))` authenticates the tenant.
6. `did.value` becomes the canonical tenant DID exposed by the internal status API.

Internal operational endpoints:

- `GET /internal/t3n/status`: readiness, network and canonical tenant DID. Returns HTTP 503 while unavailable.
- `POST /internal/t3n/reconnect`: explicitly retries a failed connection without exposing credentials.

Errors are classified and sanitized before being stored or logged. The gateway never returns `T3N_API_KEY` in HTTP responses.

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

Use `.env.example` only as a list of variable names. Inject real secrets through the deployment environment. `T3N_API_KEY` belongs only to the T3N gateway container.
