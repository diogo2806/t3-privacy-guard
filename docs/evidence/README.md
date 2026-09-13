# Evidence Bundle

This directory separates local regression controls from real Terminal 3 testnet evidence. Nothing is labelled live unless the T3N runner actually executed it.

## Dashboard proof view

The operator dashboard presents evidence in business-first order. The **Proof & evidence** view explains what the bundle proves before showing technical metadata: `PASS` is an observed outcome that matched the expected security result, `FAIL` is an observed mismatch, and `NOT_RUN` means the scenario was not executed and is never counted as proof. Contract, DID, SDK, network, trust-anchor, rollback-floor and WASM metadata remain available below that explanation so a judge can first understand the outcome and then inspect the technical linkage.

The dashboard trust flow follows the same claim boundary as the evidence bundle: `ALLOW` is not execution, accepted external execution is not completion, and `COMPLETED` is shown only after independent read-back verifies the expected external state. T3N control-plane or trust-boundary unavailability is surfaced explicitly rather than rendered as a successful state.

## Local automated evidence

From the repository root:

```bash
bash scripts/run-local-evidence.sh
```

This executes Rust policy/remediation/verification tests, including dev-only `proptest` suites that generate hundreds of policy/parser combinations, Java replay/authorization/distributed-idempotency/incident-retention tests, gateway delegation/`pii_did`/leak/trust-floor tests plus deterministic generated agent-schema invariants, and React accessibility/decision/remediation-state/evidence-provenance/retention-state tests. Raw runtime logs are gitignored.

Property tests are classified as **local invariant evidence**. A failing Rust property reports a reproducible proptest counterexample/seed; the gateway generator uses fixed documented seeds. Generated case counts are not represented as coverage percentage and never count as live T3N execution.

Optional sentinel scan:

```bash
EVIDENCE_SENTINEL_SECRET='a-long-synthetic-value' bash scripts/run-local-evidence.sh
```

## Incident-data privacy lifecycle

Incident retention is an application control, not a container-lifecycle assumption. Spring Boot normalizes `title`, `summary` and `source` before persistence, rejects high-confidence email, valid CPF, credential/token, bearer token, JWT, private-key, password and Luhn-valid payment-card candidates before the incident write, and caps accepted operational text to smaller local limits. This is **minimization, not anonymization**.

Every new incident receives server-authoritative retention metadata using the exact formula:

```text
expiresAt = createdAt + INCIDENT_RETENTION_DAYS × 24h
```

`INCIDENT_RETENTION_DAYS` defaults to `7` and is validated to the inclusive range `1..30`; the browser cannot choose it. Existing H2 rows without `expires_at` are backfilled on application startup from their original `createdAt` using the same formula.

Once `expiresAt <= now`, incident APIs stop returning the incident immediately. Startup cleanup and the scheduled purge then hard-delete dependent data in the application transaction in this order:

```text
remediation executions
        |
        v
policy decisions
        |
        v
action proposals
        |
        v
audit events
        |
        v
incident
```

No tombstone keeps `title`, `summary` or `source`. Audit messages pass through the same high-confidence sensitive-literal guard and rejected incident input is never echoed in the HTTP error. The runtime H2 database remains file-backed at `/data/privacyguard`; retention is therefore proven by application behavior rather than by destroying the container.

Local Java coverage includes the server-side expiry formula, invalid retention values, secret-sentinel rejection before persistence, audit sanitization, expired/non-expired/idempotent purge, legacy expiry backfill and a `jdbc:h2:file:` integration test that verifies `expires_at` is actually stored in a persistent H2 database. Frontend coverage verifies the visible active-retention copy; an expired incident is represented by absence from the incident API rather than by rendering purged content.

These are local privacy controls and are not presented as live T3N evidence.

## Persistent T3N trust boundary

Before tenant or agent authentication, the gateway retrieves the official signed T3N trust manifest with `fetchTrustedManifest`. The accepted manifest version is maintained as a monotonic high-water mark per network in `T3N_TRUST_FLOOR_STORE_PATH` (default `/data/t3n-trust-floor.json`). The gateway Docker image already declares `/data` as its persistent-state volume.

When a floor exists, authentication calls `fetchTrustedManifest(network, { minVersion })`. A manifest below that floor is rejected by the official SDK path. A verified manifest can only keep or advance the floor; the application never silently lowers it. Tenant and agent share the same store in the gateway runtime.

The floor file contains only public trust metadata:

- `network` (`testnet` or `production`);
- accepted numeric manifest version;
- UTC acceptance timestamp.

It contains no T3N keys, agent keys, cookies, session identifiers or provider credentials. Writes use a temporary file, file sync and rename. Missing storage on first boot is normal bootstrap. Malformed/truncated state, an invalid version, an unwritable store, or a verified anchor without an exposed monotonic version fails closed instead of resetting the floor.

There is no automatic `unsafe_trust_server` fallback for hosted testnet/production. Manually resetting the floor is an explicit recovery action because it discards rollback history; it is never performed by application code.

## One-command live proof

Prerequisites:

- valid rotated tenant `T3N_API_KEY`;
- separate funded `T3N_AGENT_API_KEY`;
- persistent `/data` storage available to the gateway, or an explicit `T3N_TRUST_FLOOR_STORE_PATH` on equivalent persistent storage;
- built release WASM at the documented path, or `T3N_CONTRACT_WASM_PATH`;
- `T3N_CONTRACT_NUMERIC_ID` when the configured contract version already exists and an operation needs its numeric id;
- synthetic `SECURITY_API_KEY`, `SECURITY_API_URL` and `SECURITY_VERIFICATION_URL` only when protected egress/read-back is enabled.

From `t3n-gateway/`:

```bash
npm install
npm run evidence:live
```

The orchestrator:

1. loads the persisted trust-manifest floor for the configured T3N network;
2. authenticates tenant and agent separately through verified trust anchors using the same monotonic floor;
3. rejects identical DIDs and refuses evidence generation unless both sessions report a verified trust anchor and a persisted floor;
4. calculates `SHA-256(WASM_BYTES)`;
5. resolves the configured live contract version or registers it when absent;
6. writes sanitized `docs/evidence/deployment-manifest.json` including trust-anchor verification, persisted rollback-floor state and the observed high-water manifest version;
7. optionally prepares the private remediation map when `EVIDENCE_PREPARE_EGRESS=true`;
8. derives least-privilege allowed hosts from the configured HTTPS action/verification endpoints;
9. delegates `evaluate-action`, `execute-remediation` and `verify-remediation` as required;
10. invokes the existing `evidence:testnet` runner;
11. verifies that testnet evidence and deployment manifest have the same network, SDK, DIDs, contract id/version and WASM hash;
12. fails if the runner reports failure, the identities mismatch, trust metadata is inconsistent, or leak detection finds configured secret material.

The evidence chain is:

```text
verified T3N trust manifest
   | signed manifest + numeric version
   v
/data/t3n-trust-floor.json
   | monotonic minVersion across restarts
   v
authenticated tenant + agent sessions
   |
   v
WASM bytes
   | SHA-256
   v
deployment-manifest.json
   | trust metadata + contract id/version + canonical DIDs
   v
T3N testnet runner
   |
   v
testnet-run.json
```

This proves linkage between the verified T3N cluster trust anchor, the persisted anti-rollback high-water mark, the local artifact used in the registration flow, the resolved T3N contract identity/version and the live scenario results. It is not described as hardware attestation unless a separate T3N API explicitly provides execution-specific attestation evidence.

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

## Generated artifacts

`deployment-manifest.json` contains only public/verifiable metadata:

- UTC timestamp;
- network;
- SDK `5.2.0`;
- canonical tenant/agent DIDs;
- `trustAnchorVerified=true` only after the official signed trust-anchor path succeeds;
- `trustManifestFloorPersisted=true` only after a valid monotonic floor is present on persistent state;
- accepted trust-manifest high-water version;
- canonical and optional numeric contract id;
- contract version;
- WASM SHA-256.

`testnet-run.json` contains live scenario outcomes including PASS/FAIL/NOT_RUN. Optional scenarios that were not executed stay `NOT_RUN`; they are never converted into PASS.

Both artifacts pass leak detection against configured tenant/agent keys, remediation key, AI provider key, service token, capability signing key and optional sentinel before being accepted.

## Trust evidence wording

The UI and evidence API deliberately distinguish three concepts:

- **Trust anchor VERIFIED**: the signed T3N manifest established the cluster trust boundary used by the authenticated sessions.
- **Rollback floor PERSISTED**: the accepted manifest-version high-water mark is stored across gateway restarts and supplied back through `minVersion`.
- **Trust manifest version**: the numeric version exposed by the verified trust anchor and persisted as the high-water mark.

These labels do not mean “hardware execution verified”. A per-request hardware-attestation claim would require separate execution-specific evidence.

If trust-manifest retrieval, rollback validation, persisted state validation or version extraction fails, live evidence generation stops. The expected operator-facing concepts are `TRUST MANIFEST UNAVAILABLE`, `ROLLBACK REJECTED`, `TRUST FLOOR CORRUPTED` and `VERSION NOT EXPOSED BY SDK`; none is presented as a green evidence state.

## Profile placeholder evidence

The policy-level logical-reference scenario can run independently. Actual `verified_email` profile resolution must remain `NOT_RUN` until a dedicated synthetic T3N profile and compatible user context are available. Unit/integration tests proving the closed mapping do not count as live profile-resolution proof.

## What is not live evidence

Mocks, unit tests, property tests, generated cases, screenshots, docs and unexecuted commands are not T3N testnet proof. The generated deployment manifest plus matching successful `testnet-run.json` are the live evidence source of truth. A screenshot of a 2xx response is not remediation completion proof; the matching verification state is required. A persisted trust floor is cluster-trust rollback protection, not execution-specific hardware attestation.

See `scenario-matrix.md` for the security-scenario mapping.
