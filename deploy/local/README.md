# Local stack

Runs the whole product on one machine as two services: [guard-runtime](../../guard-runtime/README.md) (policy, capability check, protected execution, read-back) and `app` (backend API, dashboard and MCP endpoint in one image).

## With Docker

```bash
cd deploy/local
./init-env.sh
docker compose up --build
```

`init-env.sh` writes `.env` with fresh random secrets and a new Ed25519 capability key pair; it refuses to overwrite an existing `.env`. Open http://localhost:8088 and sign in as `operator` with the `OPERATOR_PASSWORD` from `.env`.

- `policy.json` is the local policy: remediation destinations are the compose service `app` and `localhost`.
- The app's built-in security adapter plays the external security API, so revocation and notification complete and are independently verified inside the stack. In a real deployment `SECURITY_API_URL` and `SECURITY_VERIFICATION_URL` point to your own security tooling.
- The verified email behind `verified_email` is `GUARD_RUNTIME_VERIFIED_EMAIL` (default `soc@example.test`). Only guard-runtime ever holds it.
- Agents can call `http://localhost:8088/mcp` with `Authorization: Bearer <MCP_TOKEN>`.
- "Ask agent" needs an OpenAI-compatible provider: set `AI_PROVIDER=openai-compatible`, `AI_API_URL`, `AI_API_KEY` and `AI_MODEL` in `.env`. Scenarios and manual actions work without it.

This setup is for development: services use plain HTTP on the private compose network and guard-runtime runs with `GUARD_RUNTIME_ALLOW_INSECURE_HTTP=true`. A production deployment needs HTTPS endpoints, that flag off, `SESSION_COOKIE_SECURE=true`, persistent volumes backed up, and secrets from a secret manager instead of `.env`.

## Without Docker

```bash
scripts/selfhosted-e2e.sh
```

Builds the dashboard and both jars, starts guard-runtime and the app as local processes (Java 21, Maven, Node 22+), then drives a credential revocation and a private notification through the API until both are `COMPLETED`. It also checks that the app serves the dashboard, that MCP denies an unsafe proposal and rejects calls without a token, and that no secret and no verified email shows up in the logs. Ports default to 3101 and 8080; override them with `RUNTIME_PORT` and `BACKEND_PORT`. `SKIP_BUILD=1` reuses existing builds, `KEEP_WORK=1` keeps the logs.
