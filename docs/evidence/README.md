# Evidence Bundle

This directory separates local regression controls from real Terminal 3 testnet evidence. Nothing is labelled live unless the T3N runner actually executed it.

## Local automated evidence

From the repository root:

```bash
bash scripts/run-local-evidence.sh
```

This executes Rust policy/remediation/verification tests, including dev-only `proptest` suites that generate hundreds of policy/parser combinations, Java replay/authorization/distributed-idempotency tests, gateway delegation/`pii_did`/leak tests plus deterministic generated agent-schema invariants, and React accessibility/decision/remediation-state tests. Raw runtime logs are gitignored.

Property tests are classified as **local invariant evidence**. A failing Rust property reports a reproducible proptest counterexample/seed; the gateway generator uses fixed documented seeds. Generated case counts are not represented as coverage percentage and never count as live T3N execution.

Optional sentinel scan:

```bash
EVIDENCE_SENTINEL_SECRET='a-long-synthetic-value' bash scripts/run-local-evidence.sh
```

## One-command live proof

Prerequisites:

- valid rotated tenant `T3N_API_KEY`;
- separate funded `T3N_AGENT_API_KEY`;
- built release WASM at the documented path, or `T3N_CONTRACT_WASM_PATH`;
- `T3N_CONTRACT_NUMERIC_ID` when the configured contract version already exists and an operation needs its numeric id;
- synthetic `SECURITY_API_KEY`, `SECURITY_API_URL` and `SECURITY_VERIFICATION_URL` only when protected egress/read-back is enabled.

From `t3n-gateway/`:

```bash
npm install
npm run evidence:live
```

The orchestrator:

1. authenticates tenant and agent separately;
2. rejects identical DIDs;
3. calculates `SHA-256(WASM_BYTES)`;
4. resolves the configured live contract version or registers it when absent;
5. writes sanitized `docs/evidence/deployment-manifest.json`;
6. optionally prepares the private remediation map when `EVIDENCE_PREPARE_EGRESS=true`;
7. derives least-privilege allowed hosts from the configured HTTPS action/verification endpoints;
8. delegates `evaluate-action`, `execute-remediation` and `verify-remediation` as required;
9. invokes the existing `evidence:testnet` runner;
10. verifies that testnet evidence and deployment manifest have the same network, SDK, DIDs, contract id/version and WASM hash;
11. fails if the runner reports failure, the identities mismatch, or leak detection finds configured secret material.

The evidence chain is:

```text
WASM bytes
   | SHA-256
   v
deployment-manifest.json
   | contract id/version + canonical DIDs
   v
T3N testnet runner
   |
   v
testnet-run.json
```

This proves linkage between the local artifact used in the registration flow, the resolved T3N contract identity/version and the live scenario results. It is not described as hardware attestation unless a separate T3N API explicitly provides that evidence.

## Optional protected egress + independent verification proof

After the private synthetic-secret map can be prepared:

```bash
SECURITY_API_URL='https://<allowed-action-host>/<action-path>' \
SECURITY_VERIFICATION_URL='https://<allowed-readback-host>/<verification-path>' \
EVIDENCE_PREPARE_EGRESS=true \
EVIDENCE_RUN_EGRESS_NEGATIVES=true \
EVIDENCE_RUN_REMEDIATION=true \
EVIDENCE_SENTINEL_SECRET='your-synthetic-sentinel-value' \
npm run evidence:live
```

`EVIDENCE_PREPARE_EGRESS=true` requires the numeric contract id, synthetic remediation credential, action URL and independent verification URL expected by `contract:setup-remediation`. Both URLs are sealed in the private map. Their HTTPS hostnames are used to build the delegation host allowlist.

A remediation live scenario is successful only when the complete sequence is observed:

```text
attack policy = DENY
protected execution = PENDING_VERIFICATION
operation_id = present
independent read-back = VERIFIED
observed state = REVOKED
```

An HTTP 2xx or `PENDING_VERIFICATION` alone is not completion evidence. Missing operation id, contradictory state or unavailable verification is not upgraded to `PASS`.

Negative grant tests restore the known-good challenge grant in `finally`. They count as PASS only for recognizable authorization/delegation rejection; missing private configuration or transport errors are FAIL.

## Idempotency claim boundary

The application creates a durable, pessimistically locked execution claim before initiating protected egress. `requestId` is propagated as a stable `Idempotency-Key`, and replays reconcile the persisted execution state instead of intentionally initiating another egress.

This evidence does **not** claim provider-level exactly-once or at-most-once solely because that header is sent. Such a guarantee requires explicit support from the external provider. Ambiguous execution outcomes are `UNVERIFIED` and are never automatically re-executed.

## Execution correlation without raw logs

`requestId` and `traceId` are intentionally different identifiers:

- `requestId` identifies the logical action and remains stable for idempotency/replay control;
- `traceId` identifies one technical HTTP attempt and is regenerated for a new attempt unless a valid bounded `X-Trace-Id` was supplied by the browser.

The backend validates `X-Trace-Id`, places only the sanitized value in MDC, returns it in the response and propagates it to authenticated gateway calls. The gateway validates the same header only after internal service authentication and emits structured correlation events containing only bounded `traceId`, optional sanitized `requestId`, stage and state. API keys, capabilities, prompts, resolved private values, raw bodies and raw headers are not trace fields.

For an incident action, the UI obtains a sanitized timeline from:

```text
GET /api/incidents/{incidentId}/actions/{actionId}/trace
```

The timeline may contain stages such as `AGENT_PROPOSAL`, `T3N_TEE_EVALUATION`, `HUMAN_AUTHORIZATION`, `PROTECTED_EGRESS`, `EXTERNAL_ACCEPTANCE` and `EXTERNAL_VERIFICATION`. It reports the actual state observed at each stage, for example `SENT`, `ACCEPTED`, `VERIFIED`, `DENIED`, `FAILED` or `UNAVAILABLE`, plus timestamp, reason code and same-process duration when available.

A retry can therefore have the same `requestId` and a different `traceId`. This is expected and demonstrates that observability does not alter business idempotency. The Business Audit Trail remains the persistent business history; the Execution Trace explains a technical attempt; the Evidence Bundle remains the reproducible T3N/testnet proof. None substitutes for the others.

The application does not fabricate a Terminal 3 request/receipt identifier. Such an identifier must be displayed or persisted only when the platform API actually returns one.

## Generated artifacts

`deployment-manifest.json` contains only public/verifiable metadata:

- UTC timestamp;
- network;
- SDK `5.2.0`;
- canonical tenant/agent DIDs;
- canonical and optional numeric contract id;
- contract version;
- WASM SHA-256.

`testnet-run.json` contains live scenario outcomes including PASS/FAIL/NOT_RUN. Optional scenarios that were not executed stay `NOT_RUN`; they are never converted into PASS.

Both artifacts pass leak detection against configured tenant/agent keys, remediation key, AI provider key, service token, capability signing key and optional sentinel before being accepted.

## Profile placeholder evidence

The policy-level logical-reference scenario can run independently. Actual `verified_email` profile resolution must remain `NOT_RUN` until a dedicated synthetic T3N profile and compatible user context are available. Unit/integration tests proving the closed mapping do not count as live profile-resolution proof.

## What is not live evidence

Mocks, unit tests, property tests, generated cases, screenshots, docs and unexecuted commands are not T3N testnet proof. The generated deployment manifest plus matching successful `testnet-run.json` are the live evidence source of truth. A screenshot of a 2xx response is not remediation completion proof; the matching verification state is required.

See `scenario-matrix.md` for the security-scenario mapping.
