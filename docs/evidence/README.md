# Evidence Bundle

This directory separates local regression controls from real Terminal 3 testnet evidence. Nothing is labelled live unless the T3N runner actually executed it.

## Dashboard proof view

The operator dashboard presents evidence in business-first order. The **Proof & evidence** view explains what the bundle proves before showing technical metadata: `PASS` is an observed outcome that matched the expected security result, `FAIL` is an observed mismatch, and `NOT_RUN` means the scenario was not executed and is never counted as proof. Contract, DID, Agent onboarding, SDK, network, trust-anchor, rollback-floor, policy and WASM metadata remain available below that explanation so a judge can first understand the outcome and then inspect the technical linkage.

The dashboard trust flow follows the same claim boundary as the evidence bundle: `ALLOW` is not execution, accepted external execution is not completion, `REGISTERED` Agent onboarding is not delegation, an observed `ACTIVE` Member grant is not by itself effective delegated authority, and `COMPLETED` is shown only after independent read-back verifies the expected external state. T3N control-plane or trust-boundary unavailability is surfaced explicitly rather than rendered as a successful state. Operational readiness requires T3N `checkDelegation()` to confirm effective access for the authenticated Proposal Agent and Protected Executor.

## Local automated evidence

From the repository root:

```bash
bash scripts/run-local-evidence.sh
```

This executes Rust policy/remediation/verification tests, including dev-only `proptest` suites that generate hundreds of policy/parser combinations, Java replay/authorization/distributed-idempotency/incident-retention/audit-reconciliation tests, gateway Member-grant/effective-`checkDelegation`/`pii_did`/leak/trust-floor/Agent-Card tests plus deterministic generated agent-schema invariants and trace-correlation tests, and React accessibility/decision/remediation-state/evidence-provenance/onboarding/effective-authorization/retention-state tests. Raw runtime logs are gitignored.

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
execution trace events
        |
        v
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

Before tenant, Proposal Agent or Protected Executor authentication, the gateway retrieves the official signed T3N trust manifest with `fetchTrustedManifest`. The accepted manifest version is maintained as a monotonic high-water mark per network in `T3N_TRUST_FLOOR_STORE_PATH` (default `/data/t3n-trust-floor.json`). The gateway Docker image already declares `/data` as its persistent-state volume.

When a floor exists, authentication calls `fetchTrustedManifest(network, { minVersion })`. A manifest below that floor is rejected by the official SDK path. A verified manifest can only keep or advance the floor; the application never silently lowers it. Tenant, Proposal Agent and Protected Executor share the same store in the gateway runtime.

The floor file contains only public trust metadata:

- `network` (`testnet` or `production`);
- accepted numeric manifest version;
- UTC acceptance timestamp.

It contains no T3N keys, agent keys, cookies, session identifiers or provider credentials. Writes use a temporary file, file sync and rename. Missing storage on first boot is normal bootstrap. Malformed/truncated state, an invalid version, an unwritable store, or a verified anchor without an exposed monotonic version fails closed instead of resetting the floor.

There is no automatic `unsafe_trust_server` fallback for hosted testnet/production. Manually resetting the floor is an explicit recovery action because it discards rollback history; it is never performed by application code.

## Public Agent Card and effective delegation evidence

Agent authentication, public registration, Member Delegation and effective platform authorization are separate evidence dimensions.

```text
T3N_AGENT_API_KEY
      |
      v
authenticated Proposal Agent session
      |
      v
canonical Proposal Agent DID
      |
      +--> public Agent Card -> REGISTERED / NOT_REGISTERED / MISMATCH / UNAVAILABLE
      |
      +--> Member grant document -> ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
                                   |
                                   | only when ACTIVE
                                   v
                     Agent-side T3N checkDelegation
                                   |
                                   +--> authorised=true  -> effective ACTIVE
                                   +--> authorised=false -> effective INCOMPLETE
                                   +--> error/invalid    -> effective UNKNOWN
```

The same Member-grant-to-`checkDelegation()` sequence is evaluated independently for the Protected Executor using its own authenticated T3N client. The `pii_did` is always the canonical Tenant DID returned by the authenticated Tenant session. The contract id is the canonical resolved contract and functions/scopes are taken from the matching observed grant, never from browser input.

The builder derives the public card only from the canonical DID returned by the authenticated `AgentSession`. The supported public card advertises one `DID` service for that exact DID, is active, explicitly does not claim x402 support, and rejects sensitive metadata or unsupported service names. The runtime verifier resolves the public card over HTTPS, enforces the bounded schema/size, requires the DID service to match the authenticated Agent DID exactly, and hashes the exact resolved body.

Read-only verification:

```bash
cd t3n-gateway
npm install
npm run agent:card:verify
```

Explicit mutable publication:

```bash
npm run agent:card:publish
```

Publication uses the locally installed T3N CLI `agent host-card`, authenticates with the separate agent credential, derives the DID from the session and verifies the hosted card after publication. It may consume T3N credits and is therefore never run implicitly as a background or evidence-side mutation.

State meanings:

- `REGISTERED`: a public card resolved and passed the closed schema/DID/service validation;
- `NOT_REGISTERED`: no public card was found for the authenticated DID;
- `MISMATCH`: a card was returned but its schema, DID, service set or supported metadata did not match the expected agent;
- `UNAVAILABLE`: the authenticated DID or public registry could not be verified at that time;
- Member `ACTIVE`: a matching grant is present and temporally valid, but this alone does not prove effective authority;
- Effective `ACTIVE`: T3N returned `authorised=true` from `checkDelegation()` executed as the authenticated principal;
- Effective `INCOMPLETE`: no effective authorization exists for the observed request, including `authorised=false` or a non-active Member grant;
- Effective `UNKNOWN`: the platform verdict could not be validated and the system fails closed.

The deployment manifest records `agentRegistrationState` and the verification timestamp. When a card was actually resolved, it can also record the public card URI, SHA-256 and service names. A card hash is discoverability provenance only. `REGISTERED` does **not** mean delegated, authorized, TEE-attested or permitted to execute any contract function. Likewise, an `ACTIVE` Member grant is not presented as an effective authorization unless `checkDelegation()` confirms it.

## One-command live proof

Prerequisites:

- valid rotated tenant `T3N_API_KEY`;
- separate funded `T3N_AGENT_API_KEY`;
- separate funded `T3N_EXECUTOR_API_KEY` for the Protected Executor;
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
2. authenticates Tenant, Proposal Agent and Protected Executor separately through verified trust anchors using the same monotonic floor;
3. rejects identity collapse and refuses evidence generation unless the sessions report verified trust anchors and a persisted floor;
4. performs read-only public Agent Card verification for the authenticated Proposal Agent DID and records the observed registration state without confusing it with Member Delegation or effective authorization;
5. calculates `SHA-256(WASM_BYTES)`;
6. resolves the configured live contract version or registers it when absent;
7. provisions/read-backs the versioned private T3N operational policy and binds its version/hash;
8. writes sanitized `docs/evidence/deployment-manifest.json` including trust-anchor, rollback-floor, Agent Card, policy and contract/WASM provenance;
9. optionally prepares the private remediation map when `EVIDENCE_PREPARE_EGRESS=true`;
10. derives least-privilege allowed hosts from the configured HTTPS action/verification endpoints;
11. creates/updates least-privilege Member grants for Proposal Agent and Protected Executor as required by the evidence setup;
12. runtime status then distinguishes each observed Member grant from the authenticated principal-side `checkDelegation()` verdict; only effective `ACTIVE` counts as operational readiness;
13. invokes the existing `evidence:testnet` runner;
14. verifies that testnet evidence and deployment manifest have the same network, SDK, DIDs, contract id/version, WASM hash and policy provenance;
15. fails if the runner reports failure, the identities mismatch, trust/policy metadata is inconsistent, or leak detection finds configured secret material.

The evidence chain is:

```text
verified T3N trust manifest
   | signed manifest + numeric version
   v
/data/t3n-trust-floor.json
   | monotonic minVersion across restarts
   v
authenticated Tenant + Proposal Agent + Protected Executor sessions
   |                         |
   |                         +--> public Proposal Agent Card resolution
   |                              state + URI/hash/services when observed
   |
   +--> Member grants -> principal-side checkDelegation -> effective access
   v
WASM bytes + canonical policy
   | SHA-256 + policy version/hash
   v
deployment-manifest.json
   | trust + onboarding + policy + contract + canonical DIDs
   v
T3N testnet runner
   |
   v
testnet-run.json
```

This proves linkage between the verified T3N cluster trust anchor, the persisted anti-rollback high-water mark, the authenticated identities, the observed public Agent Card registration state, the local WASM/policy artifacts used in the registration/provisioning flow, the resolved T3N contract identity/version and the live scenario results. Runtime readiness additionally requires the platform-side delegation verdict described above; the evidence bundle does not infer effective authorization from a Member grant alone. It is not described as hardware attestation unless a separate T3N API explicitly provides execution-specific attestation evidence.

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