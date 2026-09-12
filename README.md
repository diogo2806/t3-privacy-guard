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

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; production deployment is expected to run services independently in containers.

## Dashboard

The React dashboard visualizes only live backend/gateway state. `GET /api/system/status` aggregates gateway reachability, authenticated tenant/agent state and the contract version resolved from T3N. An unavailable capability is displayed as unavailable rather than as successful verification.

Demo flow:

1. `Run attack scenario` creates a critical incident and evaluates an exfiltration proposal against the T3N contract.
2. The expected result is `DENY`, with the policy reason visible beside the proposal.
3. `Prepare safe remediation` creates the minimum legitimate revoke request and evaluates it separately.
4. An `ALLOW` enables `Authorize remediation`; authorization still does not execute anything.
5. `Execute protected remediation` invokes the TEE function, which rechecks policy, reads the credential from private KV and performs delegated egress.
6. The sanitized audit trail records the business flow without recording the secret.

The **Manual da Tela / Screen Manual** is available from the `BookOpen` button in the header. It documents the purpose of the screen, displayed information, actions, fields, rules, permissions, main flow and all decision/error states. UI components live exclusively in `frontend/src/components`. All CSS lives under `frontend/src/shared/styles`, with `index.css` as the only global style entry point.

## Security baseline

- Never commit `T3N_API_KEY`, `T3N_AGENT_API_KEY`, remediation credentials, or real `.env` files.
- Tenant and agent keys are separate credentials held only by the T3N gateway.
- React and Java never receive T3N private keys or the remediation API credential.
- Canonical tenant and agent DIDs come from authenticated T3N sessions (`did.value`).
- Authentication does not imply authorization; delegation scopes contract, functions, data and outbound hosts.
- `DENY`, `REDACT`, unavailable dependencies, validation failures and malformed responses fail closed.
- Java audit events contain sanitized operational metadata, never secret-bearing payloads.
- Java persists unique request ids and prior decisions/remediation results to prevent duplicate execution.

## T3N identities and delegation

The gateway authenticates tenant and agent independently with SDK 5.2.0. `T3N_AGENT_API_KEY` is a separate funded agent credential. Member delegation is written by the tenant/data-owner session with `updateMemberDelegation` and scopes access by exact contract, WIT functions, data scopes, optional read scopes, outbound hosts and validity window.

Revocation expires only the matching agent+contract grant, preserving unrelated grants. Authentication alone never grants contract access.

For every delegated contract invocation, the agent remains the authenticated caller while `pii_did` is set internally from `tenantSession.getTenantDid()`. This tells T3N which tenant/data-owner grant must be checked. `pii_did` is never accepted from React, Java, or request payloads, so callers cannot redirect authorization to another subject.

Identity and delegation endpoints:

- `GET /internal/t3n/status`
- `POST /internal/t3n/reconnect`
- `GET /internal/agent/status`
- `POST /internal/agent/connect`
- `POST /internal/agent/delegations`
- `GET /internal/agent/delegations/:contractId`
- `DELETE /internal/agent/delegations/:contractId`

## Terminal 3 integration findings

The challenge asks builders to report bugs/findings discovered while integrating. Two concrete findings shaped this implementation:

1. **Member Delegation documentation sample omits a required field.** The current Terminal 3 Member Delegation page shows `member-delegation-update` and `updateMemberDelegation` examples without `scopes`, while the field table on the same page marks `scopes` as required. Copying the snippet literally can therefore produce a rejected/incomplete grant. T3 Privacy Guard always requires and sends explicit scopes.
2. **Delegated-call target is easy to misconfigure.** The authenticated agent DID identifies the caller, but `pii_did` identifies whose grant/data authority is being used. Omitting it on a delegated call can make the node evaluate the wrong subject. T3 Privacy Guard derives `pii_did` only from the authenticated tenant/data-owner session and never accepts it from the browser or business API.

The first item is a documentation inconsistency; the second is an integration gotcha rather than a platform-security bypass.

## TEE policy contract

`contracts/privacy-guard` implements the critical policy decision in Rust/WASM rather than trusting React, Java or the LLM. Its WIT world uses Terminal 3's `generic-input` envelope and exports:

- `evaluate-action`: returns `ALLOW`, `REDACT` or `DENY`;
- `execute-remediation`: rechecks policy inside the TEE and performs protected egress only after an allowed decision.

The policy fails closed for malformed input, unknown actions, wrong purpose, invalid agent DID, direct secret disclosure and disallowed egress. `REDACT` identifies unnecessary non-secret fields without returning their values.

Replay needs durable state across calls. The WASM validates a bounded `request_id`, while the Java database makes `requestId` unique and reuses previously persisted policy/remediation results instead of executing them twice.

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

Registration uses the authenticated tenant through `TenantClient.contracts.register({ tail, version, wasm })`. The canonical contract name is `z:<tid>:<tail>` computed from the authenticated tenant DID. Runtime calls use the separately authenticated agent through `executeAndDecode`.

Contract endpoints:

- `GET /internal/contracts/privacy-guard/identity`
- `POST /internal/contracts/privacy-guard/evaluate`
- `POST /internal/contracts/privacy-guard/remediate`

## Secretless remediation

The protected-remediation path keeps the upstream credential outside the browser, Java backend and agent context:

1. register contract version `0.2.0` and record its numeric T3N `contract_id`;
2. create private `z:<tid>:secrets` with readers/writers restricted to that contract id;
3. seed `security_api_key` and `security_api_url` through the tenant control plane using `npm run contract:setup-remediation`;
4. delegate `execute-remediation` to the agent and include only the required destination hostname in `allowed_hosts`;
5. the agent sends only non-secret action metadata;
6. inside the TEE, the contract re-evaluates policy, reads the credential via `kv-store`, and sends the HTTPS request via `http-with-placeholders`;
7. only sanitized completion metadata crosses back out: request id, status, HTTP code and optional operation id.

For a reproducible public demo, `SECURITY_API_URL=https://postman-echo.com/post` is supported as a synthetic remediation adapter. Echo services return request headers in their response body, so the contract intentionally never returns or logs the raw upstream payload. Production deployments should seed a real security API endpoint and delegate only its hostname.

Terminal 3 separately enforces `allowed_hosts` from the member-delegation grant. An application bug cannot turn an undelegated destination into an allowed egress.

Setup after registration:

```bash
cd t3n-gateway
# set T3N_CONTRACT_NUMERIC_ID, SECURITY_API_KEY and SECURITY_API_URL in the runtime environment
npm run contract:setup-remediation
```

`SECURITY_API_KEY` must never appear in Git, Java, React, request payloads, logs or Dockerfiles.

## Backend incident orchestration

The Spring Boot API persists incidents, proposed actions, policy decisions, protected remediation results and audit events in an H2 file database under `/data`. A duplicate `requestId` is rejected with HTTP 409. An already persisted decision or remediation result is returned without invoking T3N/upstream again.

Business endpoints:

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

A remediation requires a persisted `ALLOW`, explicit authorization and then TEE execution. The TEE evaluates policy again immediately before egress, so Java cannot transform a previous `DENY` into a protected outbound call.

## Adversarial evidence

The repository includes a reproducible security-evidence layer instead of relying only on screenshots or claims:

- `contracts/privacy-guard/tests/adversarial.rs` exercises policy abuse, exfiltration, purpose abuse, host abuse, minimization and fail-closed cases;
- `IncidentServiceTest` covers replay, idempotency, unavailable T3N/gateway, tampered responses and authorization gates;
- gateway tests cover delegation, revocation and canonical tenant `pii_did` binding;
- the remediation regression test proves a reflected upstream secret/header cannot cross the contract result boundary;
- the evidence leak detector rejects serialized artifacts containing configured secret/sentinel values;
- `docs/evidence/scenario-matrix.md` maps each control to its executable assertion;
- `npm run evidence:testnet` creates live T3N evidence only when valid credentials/credits are available. Unexecuted live scenarios remain `NOT_RUN`, never fabricated as `PASS`.

Local regression evidence:

```bash
bash scripts/run-local-evidence.sh
```

Live testnet evidence after contract registration/delegation:

```bash
cd t3n-gateway
npm run evidence:testnet
```

Protected egress negative and attack-then-remediation scenarios require the private synthetic-secret map to be seeded first. See `docs/evidence/README.md` for the exact flags and safety rules.

## Local builds

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm test && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

## Environment

Use `.env.example` only as a variable-name template. Inject all real secrets through the deployment environment. `DATABASE_URL` can override the backend's default H2 file database.
