# guard-runtime

Self-hosted replacement for the Terminal 3 (T3N) contract host. It runs the Privacy Guard contract logic (policy evaluation, one-time remediation capability, protected execution and independent read-back) as a separate Java service, so the product works without T3N, its testnet or its credits.

The gateway selects it with `TRUST_RUNTIME=selfhosted` (see [t3n-gateway](../t3n-gateway/README.md) and [deploy/local](../deploy/local/README.md)). The T3N runtime remains available as the default.

## What replaces what

| T3N | guard-runtime |
|---|---|
| Rust/WASM `policy.rs` (`evaluate-action`) | `policy/` |
| Rust/WASM `authorization.rs` (v2 Ed25519 capability, key rotation, nonce replay) | `authorization/` |
| Rust/WASM `remediation.rs` (`execute-remediation`, `verify-remediation`) | `remediation/` |
| Private KV map `privacy-guard-policy` | `store/PolicyStore` (policy file, re-read on every call) |
| Private KV map `secrets` | `store/PrivateConfigStore` (runtime environment, same key names) |
| Private KV map `privacy-guard-execution-nonces` | `store/FileReplayStore` (same bucket layout) |
| `http-with-placeholders` host call + user profile | `egress/HttpProtectedEgress` + `store/PrivateProfileStore` |
| DID sessions + function-scoped delegation (`checkDelegation`) | `caller/CallerRegistry` (one token per caller, explicit function grants) + `GET /v1/caller` |
| Activity Log | `activity/FileActivityLog` (append-only, hash-chained) + `GET /v1/activity` |
| Private-map readiness reads | `GET /v1/readiness` |

It runs as its own process with its own credentials, apart from the gateway that talks to the AI model. That separation is what keeps the model from becoming the authority: the gateway holds a proposal token that can only evaluate and an executor token that can only execute and verify, and neither ever sees the security API key or the verified email.

## Private values

- The security API URL, verification URL and API key are read from the runtime's environment and never returned. `/v1/readiness` reports only the hostnames.
- `notify-security` carries the logical reference `verified_email` until the last moment. The contract logic builds the outbound body with the `{{profile.verified_contacts.email.value}}` marker, and only `HttpProtectedEgress` replaces it, inside the JSON string value, right before sending. The backend, gateway and model never receive the address.

## Parity with the Rust contract

- Reason codes, decision rules, error texts and response fields are unchanged. Requests keep the contract's wire format (`agent_did`, `executor_did`), so the gateway only changes the URL it calls.
- Hashes are byte-identical: the canonical policy hash, the capability `fieldsHash`/`privateRefsHash`/`normalPayloadHash`. Text handling copies Rust's semantics (Unicode `White_Space` trim, ASCII-only lowercase, UTF-8 byte lengths, code point ordering) and canonical JSON matches `serde_json`. Tests pin golden values computed by the gateway and backend implementations.
- All tests of `policy.rs`, `authorization.rs`, `remediation.rs`, `tests/adversarial.rs`, `tests/properties.rs` and `tests/remediation_properties.rs` are ported.

Intentional differences:

- **Identities.** The contract accepted any `did:t3n:` because T3N had already authenticated the caller. Here `agent_did` must be the authenticated caller for evaluation, a configured proposal agent during remediation re-evaluation, and `executor_did` must be the authenticated executor.
- **Stricter JSON.** Duplicate keys are rejected everywhere and serde's positional array form of a struct is not accepted.
- **Local development mode** (`GUARD_RUNTIME_ALLOW_INSECURE_HTTP=true`) lets security endpoints use `http://` and an explicit port. Production keeps the contract's rule: HTTPS and no port.
- Two reason texts no longer mention T3N; their codes are unchanged.

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

Function responses carry `X-Activity-Sequence` and `X-Activity-Hash`. Errors: `401 UNAUTHENTICATED`, `403 FUNCTION_NOT_GRANTED`, `400 INVALID_INPUT`, `413 INPUT_TOO_LARGE`, `422 CONTRACT_REJECTED` with the contract's `reason`.

## Configuration

| Variable | Meaning |
|---|---|
| `GUARD_RUNTIME_PORT` | HTTP port (default `3101`) |
| `GUARD_RUNTIME_POLICY_FILE` | Policy JSON. Missing → `POLICY_UNAVAILABLE`, invalid → `POLICY_INVALID` |
| `GUARD_RUNTIME_CALLERS_JSON` | `[{"id":"agent:proposal","token":"<32-512 chars>","functions":["evaluate-action"]}, …]` |
| `GUARD_RUNTIME_REPLAY_FILE` | Capability nonce store |
| `GUARD_RUNTIME_ACTIVITY_FILE` | Activity log (JSON lines). A broken hash chain stops startup |
| `GUARD_RUNTIME_TENANT_ID` | Reported as the tenant / `onBehalfOfDid` (default `default`) |
| `GUARD_RUNTIME_VERIFIED_EMAIL` | Private value behind `verified_email` |
| `SECURITY_API_URL`, `SECURITY_VERIFICATION_URL`, `SECURITY_API_KEY` | Remediation and read-back endpoints and their credential |
| `REMEDIATION_AUTH_KEY_ID`, `REMEDIATION_AUTH_PUBLIC_KEY_SPKI` | Capability verification key (DER base64 or PEM) |
| `REMEDIATION_AUTH_PREVIOUS_KEY_ID`, `REMEDIATION_AUTH_PREVIOUS_PUBLIC_KEY_SPKI`, `REMEDIATION_AUTH_PREVIOUS_KEY_GRACE_SECONDS` | Previous key during rotation (grace up to 300 s from startup) |
| `GUARD_RUNTIME_EGRESS_TIMEOUT_MS` | Outbound call timeout (default `15000`) |
| `GUARD_RUNTIME_ALLOW_INSECURE_HTTP` | Local development only |

## Build and test

Requirements: Java 21 and Maven.

```bash
mvn -f guard-runtime/pom.xml test
mvn -f guard-runtime/pom.xml package
```

`scripts/selfhosted-e2e.sh` runs the whole self-hosted stack (this runtime, gateway, backend) without Docker and drives a credential revocation and a private notification to `COMPLETED`.

## Known limits

- One runtime instance: the replay store and activity log are local files guarded by an in-process lock. Several instances need a shared transactional store.
- Single tenant per runtime.
- Caller authentication uses static bearer tokens; mTLS or OIDC workload identity is the next step.
- Without a TEE, trust rests on the separation of this process, its credentials and its operators. Confidential computing (for example AWS Nitro Enclaves or Azure confidential containers) can restore hardware isolation where required.
