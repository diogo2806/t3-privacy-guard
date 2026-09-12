# Evidence Bundle

This directory contains reproducible evidence for the T3 Privacy Guard challenge submission. It deliberately separates local automated assertions from live Terminal 3 testnet evidence.

## 1. Local automated evidence

Run from the repository root:

```bash
bash scripts/run-local-evidence.sh
```

The script executes:

- Rust unit/integration tests for policy and remediation behavior;
- Java/Spring tests for replay, fail-closed orchestration and remediation idempotency;
- Node/TypeScript gateway tests for configuration, sanitization, delegation, `pii_did` binding and leak detection;
- React tests for decision rendering and Screen Manual accessibility.

It writes runtime logs under `docs/evidence/runtime/`. These files are local execution artifacts; inspect them before publishing. The repository does not pre-populate fake PASS results.

## 2. Live T3N testnet evidence

Prerequisites:

- a valid tenant `T3N_API_KEY`;
- a separate funded `T3N_AGENT_API_KEY`;
- the `privacy-guard` contract registered on T3N testnet;
- member delegation configured for the agent;
- for protected egress scenarios, the private remediation map seeded with a synthetic test credential and `SECURITY_API_URL=https://postman-echo.com/post`.

From `t3n-gateway/`:

```bash
npm install
npm run evidence:testnet
```

This always exercises real T3N for the default live policy scenarios and writes:

```text
docs/evidence/testnet-run.json
```

The JSON includes:

- UTC generation timestamp;
- network;
- SDK version (`5.2.0`);
- canonical tenant and agent DIDs;
- canonical contract id and live version;
- SHA-256 of the local WASM artifact when available;
- expected and obtained result for every attempted scenario;
- explicit `NOT_RUN` for scenarios that require protected egress but were not enabled.

### Protected egress negative tests

Only after the private map has been seeded:

```bash
EVIDENCE_RUN_EGRESS_NEGATIVES=true npm run evidence:testnet
```

This temporarily narrows/revokes the agent grant, verifies protected egress is rejected, and restores the full grant afterward.

### Full attack-then-remediation proof

Only after the private map is seeded with a synthetic credential:

```bash
EVIDENCE_RUN_REMEDIATION=true \
EVIDENCE_SENTINEL_SECRET='your-synthetic-sentinel-value' \
npm run evidence:testnet
```

The expected outcome is a malicious request returning `DENY`, followed by a legitimate `execute-remediation` returning `COMPLETED` without the credential appearing in the output artifact.

## 3. Leak guard

Before writing `testnet-run.json`, the runner rejects the artifact if it contains any of these values available to its process:

- tenant T3N key;
- agent T3N key;
- `SECURITY_API_KEY`;
- optional `EVIDENCE_SENTINEL_SECRET`.

The detector itself has a negative unit test that intentionally places a synthetic sentinel into an artifact and expects the test to fail.

## 4. What is not evidence

Mocks, local Rust assertions and Java unit tests are useful regression controls, but they are not labelled as T3N execution. Screenshots or documentation alone are also not proof that a contract ran in the TEE. Only a generated testnet run should be cited as live T3N evidence.

See `scenario-matrix.md` for the complete mapping of security scenarios to their executable tests.
