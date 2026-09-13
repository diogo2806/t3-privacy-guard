# Evidence Bundle

This directory separates local regression controls from real Terminal 3 testnet evidence. Nothing is labelled live unless the T3N runner actually executed it.

## Dashboard proof view

The operator dashboard presents evidence in business-first order. The **Proof & evidence** view explains what the bundle proves before showing technical metadata: `PASS` is an observed outcome that matched the expected security result, `FAIL` is an observed mismatch, and `NOT_RUN` means the scenario was not executed and is never counted as proof. Contract, DID, SDK, network, trust-anchor, rollback-floor, public Agent Card and WASM metadata remain available below that explanation so a judge can first understand the outcome and then inspect the technical linkage.

The dashboard trust flow follows the same claim boundary as the evidence bundle: `ALLOW` is not execution, accepted external execution is not completion, and `COMPLETED` is shown only after independent read-back verifies the expected external state. T3N control-plane or trust-boundary unavailability is surfaced explicitly rather than rendered as a successful state.

## Local automated evidence

From the repository root:

```bash
bash scripts/run-local-evidence.sh
```

This executes Rust policy/remediation/verification tests, including dev-only `proptest` suites that generate hundreds of policy/parser combinations, Java replay/authorization/distributed-idempotency tests, gateway delegation/`pii_did`/leak/trust-floor/Agent-Card tests plus deterministic generated agent-schema invariants, and React accessibility/decision/remediation-state/evidence-provenance tests. Raw runtime logs are gitignored.

Property tests are classified as **local invariant evidence**. A failing Rust property reports a reproducible proptest counterexample/seed; the gateway generator uses fixed documented seeds. Generated case counts are not represented as coverage percentage and never count as live T3N execution.

Optional sentinel scan:

```bash
EVIDENCE_SENTINEL_SECRET='a-long-synthetic-value' bash scripts/run-local-evidence.sh
```

## Persistent T3N trust boundary

Before tenant or agent authentication, the gateway retrieves the official signed T3N trust manifest with `fetchTrustedManifest`. The accepted manifest version is maintained as a monotonic high-water mark per network in `T3N_TRUST_FLOOR_STORE_PATH` (default `/data/t3n-trust-floor.json`). The gateway Docker image already declares `/data` as its persistent-state volume.

When a floor exists, authentication calls `fetchTrustedManifest(network, { minVersion })`. A manifest below that floor is rejected by the official SDK path. A verified manifest can only keep or advance the floor; the application never silently lowers it. Tenant and agent share the same store in the gateway runtime.

The floor file contains only public trust metadata:

- `network` (`testnet` or `production`);
- accepted numeric manifest version;
- UTC acceptance timestamp.

It contains no T3N keys, agent keys, cookies, session identifiers or provider credentials. Writes use a temporary file, file sync and rename. Missing storage on first boot is normal bootstrap. Malformed/truncated state, an invalid version, an unwritable store, or a verified anchor without an exposed monotonic version fails closed instead of resetting the floor.

There is no automatic `unsafe_trust_server` fallback for hosted testnet/production. Manually resetting the floor is an explicit recovery action because it discards rollback history; it is never performed by application code.

## Public Agent Card onboarding evidence

Agent authentication, public registration and Member Delegation are three separate observations:

- `AUTHENTICATED`: the configured agent key established a T3N session and `AgentSession.getAgentDid()` returned the canonical Agent DID;
- `REGISTERED`: the public Agent Card resolved from T3N, matched that authenticated DID, passed the supported schema/size checks, remained active and advertised only implemented services;
- `DELEGATED`: the tenant granted contract functions, scopes and hosts. This remains the authorization boundary.

Public registration is discoverability, not contract permission and not TEE attestation. The read-only verification command is deliberately separate from the mutating publication command:

```bash
cd t3n-gateway
npm install
npm run agent:card:verify
npm run agent:card:publish
```

`agent:card:verify` performs no mutation and exits non-zero unless the observed state is `REGISTERED`. `agent:card:publish` is an explicit mutable operation that may consume T3N credits. It builds the deterministic card from the authenticated Agent DID, uses only the pinned local T3N CLI/SDK `5.2.0`, passes the agent API key through the child-process environment rather than command-line arguments, then verifies the public card after publication. The generated local `agent-card.json` is gitignored.

The public card advertises only the implemented `DID` service. `x402Support` is false and the project does not claim A2A, MCP, x402 or unsupported trust/attestation services through the card.

Observed onboarding states are fail-closed:

- `REGISTERED`: resolved card is valid and bound to the authenticated Agent DID;
- `NOT_REGISTERED`: public resolution returned no card;
- `MISMATCH`: a card resolved, but DID/schema/activity/services did not match the supported agent identity;
- `UNAVAILABLE`: registration could not be verified, including network/resolver failure.

Only `REGISTERED` is rendered as a success state. None of these states changes Member Delegation.

## One-command live proof

Prerequisites:

- valid rotated tenant `T3N_API_KEY`;
- separate funded `T3N_AGENT_API_KEY`;
- public Agent Card already published when submission evidence is expected to show `REGISTERED`;
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
4. resolves the public Agent Card read-only and records its explicit registration state without publishing or granting authority;
5. calculates `SHA-256(WASM_BYTES)`;
6. resolves the configured live contract version or registers it when absent;
7. writes sanitized `docs/evidence/deployment-manifest.json` including Agent Card state/URI/hash/verification time/services, trust-anchor verification, persisted rollback-floor state and the observed high-water manifest version;
8. optionally prepares the private remediation map when `EVIDENCE_PREPARE_EGRESS=true`;
9. derives least-privilege allowed hosts from the configured HTTPS action/verification endpoints;
10. delegates `evaluate-action`, `execute-remediation` and `verify-remediation` as required;
11. invokes the existing `evidence:testnet` runner;
12. verifies that testnet evidence and deployment manifest have the same network, SDK, DIDs, contract id/version and WASM hash;
13. fails if the runner reports failure, the identities mismatch, trust metadata is inconsistent, or leak detection finds configured secret material.

The evidence chain is:

```text
verified T3N trust manifest
   | signed manifest + numeric version
   v
/data/t3n-trust-floor.json
   | monotonic minVersion across restarts
   v
authenticated tenant + agent sessions
   | canonical Agent DID
   v
public T3N Agent Card resolver
   | state + URI + SHA-256 + services + verifiedAt
   v
WASM bytes
   | SHA-256
   v
deployment-manifest.json
   | trust metadata + onboarding evidence + contract id/version + canonical DIDs
   v
T3N testnet runner
   |
   v
testnet-run.json
```

This proves linkage between the verified T3N cluster trust anchor, the persisted anti-rollback high-water mark, the authenticated Agent DID, the observed public onboarding metadata, the local artifact used in the contract registration flow, the resolved T3N contract identity/version and the live scenario results. Agent registration is not described as Member Delegation or hardware attestation, and cluster trust is not described as per-request hardware attestation unless a separate T3N API explicitly provides execution-specific attestation evidence.

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
- observed Agent Card state;
- public Agent Card URI when resolved;
- SHA-256 of the raw resolved Agent Card when available;
- Agent Card verification timestamp and verified service names;
- `trustAnchorVerified=true` only after the official signed trust-anchor path succeeds;
- `trustManifestFloorPersisted=true` only after a valid monotonic floor is present on persistent state;
- accepted trust-manifest high-water version;
- canonical and optional numeric contract id;
- contract version;
- WASM SHA-256.

A `REGISTERED` claim is accepted by the evidence API only when the URI is HTTPS, the card hash is a valid SHA-256 and the verified service set is exactly the supported `DID` service. Negative registration states are preserved as negative/non-ready evidence instead of being upgraded to success.

`testnet-run.json` contains live scenario outcomes including PASS/FAIL/NOT_RUN. Optional scenarios that were not executed stay `NOT_RUN`; they are never converted into PASS.

Both artifacts pass leak detection against configured tenant/agent keys, remediation key, AI provider key, service token, capability signing key and optional sentinel before being accepted.

## Trust evidence wording

The UI and evidence API deliberately distinguish these concepts:

- **Trust anchor VERIFIED**: the signed T3N manifest established the cluster trust boundary used by the authenticated sessions.
- **Rollback floor PERSISTED**: the accepted manifest-version high-water mark is stored across gateway restarts and supplied back through `minVersion`.
- **Trust manifest version**: the numeric version exposed by the verified trust anchor and persisted as the high-water mark.
- **Agent onboarding REGISTERED**: a public Agent Card resolved and matched the authenticated Agent DID and supported service schema. It is discoverability evidence only.
- **Member Delegation ACTIVE**: the tenant granted the observed contract functions/scopes/hosts and remains the T3N authorization source.

These labels do not mean “hardware execution verified”. A per-request hardware-attestation claim would require separate execution-specific evidence.

If trust-manifest retrieval, rollback validation, persisted state validation or version extraction fails, live evidence generation stops. The expected operator-facing concepts are `TRUST MANIFEST UNAVAILABLE`, `ROLLBACK REJECTED`, `TRUST FLOOR CORRUPTED` and `VERSION NOT EXPOSED BY SDK`; none is presented as a green evidence state.

## Profile placeholder evidence

The policy-level logical-reference scenario can run independently. Actual `verified_email` profile resolution must remain `NOT_RUN` until a dedicated synthetic T3N profile and compatible user context are available. Unit/integration tests proving the closed mapping do not count as live profile-resolution proof.

## What is not live evidence

Mocks, unit tests, property tests, generated cases, local Agent Card JSON, screenshots, docs and unexecuted commands are not T3N testnet proof. A locally generated Agent Card does not prove remote registration; only read-only public resolution that produces `REGISTERED` proves the onboarding state. The generated deployment manifest plus matching successful `testnet-run.json` are the live evidence source of truth. A screenshot of a 2xx response is not remediation completion proof; the matching verification state is required. A persisted trust floor is cluster-trust rollback protection, not execution-specific hardware attestation.

See `scenario-matrix.md` for the security-scenario mapping.
