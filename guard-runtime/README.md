# guard-runtime

Self-hosted replacement for the Terminal 3 (T3N) contract host. It runs the Privacy Guard contract logic as a separate Java service, so the product works without T3N, its testnet or its credits.

Status: **spike**. Only `evaluate-action` is ported. `execute-remediation` and `verify-remediation` still exist only in the Rust contract (`contracts/privacy-guard`).

## What replaces what

| T3N | guard-runtime |
|---|---|
| Rust contract `policy.rs` compiled to WASM | `policy/PolicyDocumentParser` and `policy/PolicyEvaluator` |
| Private KV map `privacy-guard-policy` / `current` | `store/PolicyStore` (file-backed for now) |
| DID sessions + function-scoped delegation (`checkDelegation`) | `caller/CallerRegistry`: one bearer token per caller, explicit function grants |
| `executeAndDecode(contract, "evaluate-action", ...)` | `POST /v1/functions/evaluate-action` |

The runtime is meant to run as its own process with its own credentials, apart from the gateway that talks to the AI model. That separation is what keeps the model from becoming the authority.

## Parity with the Rust contract

- Reason codes, decision rules and response fields are unchanged. The request keeps the contract's wire format (`agent_did` included), so the gateway only has to change the URL it calls.
- The policy hash is byte-identical. Text handling copies Rust's semantics (Unicode `White_Space` trim, ASCII-only lowercase, UTF-8 byte lengths, code point ordering) and the canonical JSON matches `serde_json`'s output. Tests check it against golden hashes from the gateway's TypeScript canonicalizer, including for `t3n-gateway/policy/privacy-guard-policy.json`.
- All tests in `policy.rs`, `tests/adversarial.rs` and `tests/properties.rs` are ported (`src/test/java/.../policy`).

Intentional differences:

- **Agent identity.** The contract accepted any `did:t3n:` prefix because T3N had already authenticated the caller. Here `agent_did` must equal the id of the caller the runtime authenticated; otherwise the answer is `DENY INVALID_AGENT_DID`.
- **Wording.** Two reason texts no longer mention T3N. Their codes are unchanged.
- **Stricter JSON.** Duplicate keys are rejected everywhere (serde lets the last one win inside maps), and so is serde's positional array form of a struct.

## Run locally

Requirements: Java 21 and Maven.

```bash
mvn -f guard-runtime/pom.xml test
mvn -f guard-runtime/pom.xml package -DskipTests
```

Configuration (environment variables):

| Variable | Meaning |
|---|---|
| `GUARD_RUNTIME_PORT` | HTTP port (default `3101`) |
| `GUARD_RUNTIME_POLICY_FILE` | Policy JSON, re-read on every call. Missing → `POLICY_UNAVAILABLE`, invalid → `POLICY_INVALID` |
| `GUARD_RUNTIME_CALLERS_JSON` | `[{"id":"agent:proposal","token":"<32-512 chars>","functions":["evaluate-action"]}]` |

Responses: `200` with the policy decision (ALLOW, REDACT or DENY), `401 UNAUTHENTICATED`, `403 FUNCTION_NOT_GRANTED`, `400 INVALID_INPUT`, `413 INPUT_TOO_LARGE`.

## Next steps

1. Port `authorization.rs` (one-time Ed25519 capability plus replay store) and `remediation.rs` (minimized egress, private-value placeholder resolution, independent read-back). After that the gateway can start without T3N credentials.
2. Move the policy, secrets and replay state from files to an encrypted database store, and authenticate callers with mTLS or OIDC workload identity instead of static tokens.

## Using it from the gateway

Set `TRUST_RUNTIME=selfhosted` in `t3n-gateway` together with `GUARD_RUNTIME_URL`, `GUARD_RUNTIME_TOKEN` and `GUARD_RUNTIME_AGENT_ID` (see `.env.example`). `/internal/contracts/privacy-guard/evaluate`, the MCP tool `privacy.evaluate_action` and A2A evaluation then call this service. The gateway overwrites any `agent_did` sent by its clients with `GUARD_RUNTIME_AGENT_ID`, and logs the trace stage as `GUARD_RUNTIME_EVALUATION` instead of `T3N_TEE_EVALUATION`. Remediation and verification still go to T3N.
