# Evidence Bundle

This directory separates local regression controls from real Terminal 3 testnet evidence. Nothing is labelled live unless the T3N runner actually executed it.

## Local automated evidence

From the repository root:

```bash
bash scripts/run-local-evidence.sh
```

This executes Rust policy/remediation tests, Java replay/authorization/idempotency tests, gateway delegation/`pii_did`/leak tests and React accessibility/decision tests. Raw runtime logs are gitignored.

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
- synthetic `SECURITY_API_KEY`/`SECURITY_API_URL` only when protected egress is enabled.

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
7. writes the minimum challenge delegation;
8. invokes the existing `evidence:testnet` runner;
9. verifies that testnet evidence and deployment manifest have the same network, SDK, DIDs, contract id/version and WASM hash;
10. fails if the runner reports failure, the identities mismatch, or leak detection finds configured secret material.

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

## Optional protected egress proof

After the private synthetic-secret map can be prepared:

```bash
EVIDENCE_PREPARE_EGRESS=true \
EVIDENCE_RUN_EGRESS_NEGATIVES=true \
EVIDENCE_RUN_REMEDIATION=true \
EVIDENCE_SENTINEL_SECRET='your-synthetic-sentinel-value' \
npm run evidence:live
```

`EVIDENCE_PREPARE_EGRESS=true` requires the numeric contract id, plus the synthetic remediation URL/key expected by `contract:setup-remediation`.

Negative grant tests restore the known-good challenge grant in `finally`. They count as PASS only for recognizable authorization/delegation rejection; missing private configuration or transport errors are FAIL.

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

Both artifacts pass the leak detector against tenant key, agent key, remediation key and optional sentinel before being accepted.

## What is not live evidence

Mocks, unit tests, screenshots, docs and unexecuted commands are not T3N testnet proof. The generated deployment manifest plus matching successful `testnet-run.json` are the live evidence source of truth.

See `scenario-matrix.md` for the security-scenario mapping.
