# guard-runtime

The trust runtime of Privacy Guard: a separate Java service that holds the policy, the private values and the credentials for the security API, and that is the only component allowed to cause a real side effect. It evaluates proposed actions (ALLOW, REDACT or DENY), verifies the one-time human authorization capability, performs the minimized protected call and reads the result back independently.

It runs as its own process with its own credentials, apart from the app that talks to the AI model. That separation keeps the model from becoming the authority: the app holds a proposal token that can only evaluate and an executor token that can only execute and verify, and neither the app nor the model ever sees the security API key or the verified email.

## Modules

| Package | Responsibility |
|---|---|
| `policy/` | `evaluate-action`: action, purpose, fields, destination and private references against the policy |
| `authorization/` | v2 Ed25519 capability: signature, expiry, exact binding to the approved request, key rotation window, nonce replay buckets |
| `remediation/` | `execute-remediation` (destination binding, policy re-check, minimized payload) and `verify-remediation` (independent read-back) |
| `store/` | Policy (a file, or immutable versions with a hash-chained history), private configuration from the environment, replay store, private profile |
| `egress/` | Protected HTTP call; the only place where `verified_email` becomes a real address |
| `caller/` | Bearer-token callers with explicit function grants |
| `activity/` | Append-only, hash-chained activity log |

## Private values

- The security API URL, verification URL and API key are read from the runtime's environment and never returned. `/v1/readiness` reports only the hostnames.
- `notify-security` carries the logical reference `verified_email` until the last moment. The outbound body is built with the `{{profile.verified_contacts.email.value}}` marker, and only `HttpProtectedEgress` replaces it, inside the JSON string value, right before sending. The app and the model never receive the address.

## Guarantees

- **Identities.** For evaluation `agent_did` must be the authenticated caller; during remediation it must be a configured proposal caller and `executor_did` the authenticated executor.
- **Destination binding.** The hostname the human approved is signed into the capability and must equal the hostname of the configured security API at execution time, before policy re-check and before any HTTP call (`EXECUTION_DESTINATION_CHANGED` otherwise).
- **Minimization.** Only trusted normal values whose keys survive the current policy are sent; forbidden secret fields are denied; a REDACT decision proceeds only if the action's required fields survive and the minimized set re-evaluates to ALLOW.
- **One use.** A capability nonce is burned before egress; replay is rejected even across restarts.
- **Completion is observed, not assumed.** An HTTP 2xx is acceptance. Completion needs a read-back that matches the same opaque operation id and the action's closed state (`REVOKED`, or `DELIVERED` with `recipient_resolved=true`).
- **Deterministic hashes.** The policy hash and the capability `fieldsHash`/`privateRefsHash`/`normalPayloadHash` use canonical JSON with fixed text semantics (Unicode `White_Space` trim, ASCII-only lowercase, UTF-8 byte lengths, code point ordering); tests pin golden values shared with the app.
- **Strict input.** Duplicate JSON keys and positional array forms are rejected; sizes are bounded.

## API

All endpoints need `Authorization: Bearer <caller token>`.

| Endpoint | Grant | Notes |
|---|---|---|
| `POST /v1/functions/evaluate-action` | `evaluate-action` | Policy decision (ALLOW, REDACT or DENY) |
| `POST /v1/functions/execute-remediation` | `execute-remediation` | Verifies and burns the capability, then performs the minimized egress |
| `POST /v1/functions/verify-remediation` | `verify-remediation` | Independent read-back |
| `GET /v1/caller` | any | Caller id and granted functions |
| `GET /v1/readiness` | any | Policy, endpoint hostnames and which private settings are present |
| `GET /v1/activity?beforeSeq&fromMs&toMs&limit` | any | Activity log, newest first |
| `GET /v1/policy` | `manage-policy` | Active version, hash and canonical document; `managed` says whether versions can be published |
| `GET /v1/policy/history?limit` | `manage-policy` | Seeds, publications and rollbacks, newest first, with caller and requester |
| `GET /v1/policy/versions/{version}` | `manage-policy` | A published version |
| `POST /v1/policy/validate` | `manage-policy` | `{"document":{...}}` returns `valid` with version and hash, or the rule it breaks |
| `POST /v1/policy/publish` | `manage-policy` | `{"document":{...},"expected_current_hash":"...","requested_by":"..."}` |
| `POST /v1/policy/rollback` | `manage-policy` | `{"version":"...","expected_current_hash":"...","requested_by":"..."}` |

Function responses carry `X-Activity-Sequence` and `X-Activity-Hash`; so do publish and rollback, which are logged as `manage-policy`. Policy errors: `422 POLICY_INVALID` with the rule it breaks, `409 POLICY_CHANGED` (the expected hash is not the active one), `409 VERSION_EXISTS` (versions are immutable), `404 VERSION_NOT_FOUND`, `409 POLICY_MANAGEMENT_DISABLED` without a policy directory. Errors: `401 UNAUTHENTICATED`, `403 FUNCTION_NOT_GRANTED`, `400 INVALID_INPUT`, `413 INPUT_TOO_LARGE`, `422 CONTRACT_REJECTED` with a `reason` code.

## Configuration

| Variable | Meaning |
|---|---|
| `GUARD_RUNTIME_PORT` | HTTP port (default `3101`) |
| `GUARD_RUNTIME_POLICY_FILE` | Policy JSON. Missing → `POLICY_UNAVAILABLE`, invalid → `POLICY_INVALID`. With a policy directory it only seeds versions not published yet |
| `GUARD_RUNTIME_POLICY_DIR` | Optional. Versions (written once) and `history.jsonl` (hash-chained; a broken chain or an altered active version stops startup). Enables `/v1/policy` writes |
| `GUARD_RUNTIME_CALLERS_JSON` | `[{"id":"agent:proposal","token":"<32-512 chars>","functions":["evaluate-action"]}, …]`; grants are `evaluate-action`, `execute-remediation`, `verify-remediation` and `manage-policy` |
| `GUARD_RUNTIME_REPLAY_FILE` | Capability nonce store |
| `GUARD_RUNTIME_ACTIVITY_FILE` | Activity log (JSON lines). A broken hash chain stops startup |
| `GUARD_RUNTIME_TENANT_ID` | Reported as the tenant / `onBehalfOfDid` (default `default`) |
| `GUARD_RUNTIME_VERIFIED_EMAIL` | Private value behind `verified_email` |
| `SECURITY_API_URL`, `SECURITY_VERIFICATION_URL`, `SECURITY_API_KEY` | Remediation and read-back endpoints and their credential |
| `REMEDIATION_AUTH_KEY_ID`, `REMEDIATION_AUTH_PUBLIC_KEY_SPKI` | Capability verification key (DER base64 or PEM) |
| `REMEDIATION_AUTH_PREVIOUS_KEY_ID`, `REMEDIATION_AUTH_PREVIOUS_PUBLIC_KEY_SPKI`, `REMEDIATION_AUTH_PREVIOUS_KEY_GRACE_SECONDS` | Previous key during rotation (grace up to 300 s from startup) |
| `GUARD_RUNTIME_EGRESS_TIMEOUT_MS` | Outbound call timeout (default `15000`) |
| `GUARD_RUNTIME_TLS_ENABLED`, `GUARD_RUNTIME_TLS_CERTIFICATE`, `GUARD_RUNTIME_TLS_PRIVATE_KEY` | Serve the API over TLS (PEM files) |
| `GUARD_RUNTIME_TLS_CLIENT_AUTH`, `GUARD_RUNTIME_TLS_CLIENT_CA` | `need` plus the CA of the app's client certificate for mutual TLS |
| `GUARD_RUNTIME_METRICS_TOKEN` | Bearer token for `/actuator/prometheus` (`guard_runtime_calls_total` by function and outcome, JVM, HTTP) |
| `GUARD_RUNTIME_ALLOW_INSECURE_HTTP` | Local development only: allows `http://` and explicit ports for the security API. Production requires HTTPS without a port |

## Build and test

Requirements: Java 21 and Maven.

```bash
mvn -f guard-runtime/pom.xml test
mvn -f guard-runtime/pom.xml package
```

`scripts/selfhosted-e2e.sh` runs both services without Docker and drives a credential revocation and a private notification to `COMPLETED`.

## Known limits

- One runtime instance: the replay store, activity log and policy versions are local files guarded by an in-process lock. Several instances need a shared transactional store.
- Single tenant per runtime.
- Caller authentication uses static bearer tokens, optionally inside mutual TLS; workload identity is not supported.
- One private value (`verified_email`) and one security API per runtime.
- Without a TEE, trust rests on the separation of this process, its credentials and its operators. Confidential computing (for example AWS Nitro Enclaves or Azure confidential containers) can add hardware isolation where required.

## Origin

The logic was ported from the Rust/WASM contract the project originally ran on Terminal 3; reason codes, decision rules and wire fields (`agent_did`, `executor_did`) were kept. That version is preserved under the git tags `competition-final` and `dual-runtime`.
