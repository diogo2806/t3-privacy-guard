# Evidence Bundle

This directory separates local regression controls from real Terminal 3 testnet evidence. Nothing is labelled live unless the T3N runner actually executed it.

## Dashboard proof view

The operator dashboard presents evidence in business-first order. The **Proof & evidence** view explains what the bundle proves before showing technical metadata: `PASS` is an observed outcome that matched the expected security result, `FAIL` is an observed mismatch, and `NOT_RUN` means the scenario was not executed and is never counted as proof. Source commit/tree state, contract, DID, Agent onboarding, SDK, network, trust-anchor, rollback-floor, policy and WASM metadata remain available below that explanation so a judge can first understand the outcome and then inspect the technical linkage.

`Source commit` is the full 40-character Git revision captured before evidence generation starts. `Source tree` is `CLEAN` only when that revision had no tracked or untracked working-tree changes at capture time; otherwise it is explicitly `DIRTY`. This source identity links the bundle to public code, but it does not replace the WASM SHA-256 or policy hash and is not an independent code audit.

The dashboard trust flow follows the same claim boundary as the evidence bundle: `ALLOW` is not execution, accepted external execution is not completion, `REGISTERED` Agent onboarding is not delegation, an observed `ACTIVE` Member grant is not by itself effective delegated authority, and `COMPLETED` is shown only after independent read-back verifies the expected external state. T3N control-plane or trust-boundary unavailability is surfaced explicitly rather than rendered as a successful state. Operational readiness requires T3N `checkDelegation()` to confirm effective access for the authenticated Proposal Agent and Protected Executor.

The denied-to-legitimate demo follows the same evidence rule. After a malicious proposal is denied, **Ask agent for minimum proposal** invokes the same configured provider again inside the existing incident. The application does not create a fixed safe action. The second provider/model origin is persisted in the authenticated local audit chain, and the exact model output is independently evaluated by T3N. `DENY`, `REDACT` or an unsupported action remains visible without fallback.

The dashboard also presents **local audit integrity** separately from T3N Activity Log provenance. `VERIFIED` means the retained application HMAC chain and authenticated head verified with configured key versions. It does not mean immutable storage, T3N execution proof or hardware attestation. A T3N `MATCHED` event and a local `BROKEN` chain are different signals and can coexist.

## Local automated evidence

From the repository root:

```bash
bash scripts/run-local-evidence.sh
```

This executes Rust policy/remediation/verification tests, including dev-only `proptest` suites that generate hundreds of policy/parser combinations, Java replay/authorization/distributed-idempotency/incident-retention/audit-integrity/audit-reconciliation tests, gateway Member-grant/effective-`checkDelegation`/`pii_did`/leak/trust-floor/Agent-Card tests plus deterministic generated agent-schema invariants and trace-correlation tests, and React accessibility/decision/remediation-state/evidence-provenance/local-audit-integrity/onboarding/effective-authorization/retention-state tests. The agent flow additionally verifies that a second prompt reuses the same incident, creates a distinct provider-generated proposal, is independently evaluated, records provider/model audit provenance, and creates no synthetic fallback action when the provider fails. Frontend tests verify the agent-driven CTA and the prompt-only existing-incident API contract. Raw runtime logs are gitignored.

Local audit-integrity coverage includes a fixed canonical HMAC vector, one/many-event chains, content/link/sequence/provenance tampering, missing head, retained-tail deletion, manual insertion, concurrent append linearity, key mismatch/restart, explicit key rotation, legacy history and the protected-change fail-closed guard. These are local invariant tests, not T3N testnet evidence.

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
audit chain head
        |
        v
audit events
        |
        v
incident
```

No tombstone keeps `title`, `summary` or `source`. Audit messages pass through the same high-confidence sensitive-literal guard and rejected incident input is never echoed in the HTTP error. The runtime H2 database remains file-backed at `/data/privacyguard`; retention is therefore proven by application behavior rather than by destroying the container. The chain head is not retained indefinitely merely to preserve an integrity claim after the incident data itself is purged.

Local Java coverage includes the server-side expiry formula, invalid retention values, secret-sentinel rejection before persistence, audit sanitization, audit-chain/head deletion, expired/non-expired/idempotent purge, legacy expiry backfill and a `jdbc:h2:file:` integration test that verifies `expires_at` is actually stored in a persistent H2 database. Frontend coverage verifies the visible active-retention copy; an expired incident is represented by absence from the incident API rather than by rendering purged content.

These are local privacy/integrity controls and are not presented as live T3N evidence.

## Tamper-evident local audit boundary

New sanitized business-audit events are stored in a versioned HMAC-SHA-256 chain scoped to the incident. The canonical event input binds incident/event IDs, monotonic local sequence, type, canonical UTC timestamp, sanitized message, previous MAC and persisted T3N sequence/hash/function when present. A separately HMAC-authenticated chain head binds the final retained sequence/MAC and key version.

Agent-generated actions also add a sanitized `AGENT_PROPOSAL_SOURCE` event after proposal persistence and before T3N policy evaluation. That event identifies the action plus bounded provider/model labels. It does not contain the prompt, provider key, tool-call raw response, credentials or private values. This gives retained local evidence that two actions in the same incident came from two separate model proposals rather than an application-authored fallback.

Append is serialized by a pessimistic lock on the incident. Verification checks sequence continuity, previous-MAC linkage, event MACs, required key versions and the authenticated head. This detects DB-only edits, inserted rows, sequence/link changes, T3N-provenance metadata changes, missing head and retained-tail deletion when the attacker does not possess the HMAC key.

Runtime key configuration is explicit:

```text
AUDIT_INTEGRITY_KEY
AUDIT_INTEGRITY_KEY_ID
AUDIT_INTEGRITY_PREVIOUS_KEYS
AUDIT_INTEGRITY_ALLOW_LEGACY_BOOTSTRAP=false
```

The active key must be a separate backend-only secret. Planned rotation changes the key id and retains only the historical `keyId=secret` material still needed for retained events. Pre-HMAC events remain `LEGACY_UNVERIFIED`; normal runtime does not silently create a new trust root over legacy rows.

The claim is deliberately limited. This is **tamper-evident**, not immutable/tamper-proof storage. A compromised backend that can use the key, simultaneous DB+key compromise, or restoration of an older complete internally consistent DB snapshot is outside this guarantee unless a separate monotonic external audit anchor is introduced. HMAC state is not a T3N attestation claim.

Protected local changes fail closed on `BROKEN`, `KEY_MISMATCH` or otherwise unverifiable retained history. The verifier does not repair or re-MAC a broken chain automatically.

## Persistent T3N trust boundary

Before Tenant, Proposal Agent or Protected Executor authentication, the gateway retrieves the official signed T3N trust manifest with `fetchTrustedManifest`. The accepted manifest version is maintained as a monotonic high-water mark per network in `T3N_TRUST_FLOOR_STORE_PATH` (default `/data/t3n-trust-floor.json`). The gateway Docker image already declares `/data` as its persistent-state volume.

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
                                   +--> authorised=false -> effective DENIED
                                   +--> error/invalid    -> effective UNKNOWN
```

The same Member-grant-to-`checkDelegation()` sequence is evaluated independently for the Protected Executor using its own authenticated T3N client. The `pii_did` is always the canonical Tenant DID returned by the authenticated Tenant session and the contract id is the canonical resolved contract. The check does not trust restrictions read back from the grant as its requested authorization surface: Proposal always checks exactly `evaluate-action` with scopes `incident_id`, `credential_id`, `reason`; Executor independently checks exactly `execute-remediation` plus `verify-remediation` with the same minimum scopes. Wildcard function/scope requirements are rejected. Browser input cannot choose any of these security inputs.

When the Member grant is not `ACTIVE`, runtime status does not issue a potentially misleading positive `checkDelegation()` call: `SCHEDULED`, `REVOKED` and `NOT_GRANTED` map fail-closed to effective `DENIED`, while unreadable/invalid Member state maps to effective `UNKNOWN`. `checkedFunctions` and `checkedScopes` remain empty when no effective check was attempted.

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

Publication uses the locally installed T3N CLI `agent host-card`, authenticates with the separate Proposal Agent credential, derives the DID from the session and verifies the hosted card after publication. It may consume T3N credits and is therefore never run implicitly as a background or evidence-side mutation.

State meanings:

- `REGISTERED`: a public card resolved and passed the closed schema/DID/service validation;
- `NOT_REGISTERED`: no public card was found for the authenticated DID;
- `MISMATCH`: a card was returned but its schema, DID, service set or supported metadata did not match the expected agent;
- `UNAVAILABLE`: the authenticated DID or public registry could not be verified at that time;
- Member `ACTIVE`: a matching grant is present and temporally valid, but this alone does not prove effective authority;
- Effective `ACTIVE`: T3N returned `authorised=true` from `checkDelegation()` executed as the authenticated principal for its fixed minimum requirements;
- Effective `DENIED`: T3N returned `authorised=false`, or a known non-active Member state prevents effective authorization;
- Effective `UNKNOWN`: the Member state or platform verdict could not be validated and the system fails closed.

The deployment manifest records `agentRegistrationState` and the verification timestamp. When a card was actually resolved, it can also record the public card URI, SHA-256 and service names. A card hash is discoverability provenance only. `REGISTERED` does **not** mean delegated, authorized, TEE-attested or permitted to execute any contract function. Likewise, an `ACTIVE` Member grant is not presented as an effective authorization unless `checkDelegation()` confirms it.

## One-command live proof

Prerequisites:

- valid rotated Tenant `T3N_API_KEY`;
- separate funded `T3N_AGENT_API_KEY`;
- separate funded `T3N_EXECUTOR_API_KEY` for the Protected Executor;
- persistent `/data` storage available to the gateway, or an explicit `T3N_TRUST_FLOOR_STORE_PATH` on equivalent persistent storage;
- built release WASM at the documented path, or `T3N_CONTRACT_WASM_PATH`;
- a clean Git working tree for submission evidence;
- `T3N_CONTRACT_NUMERIC_ID` when the configured contract version already exists and an operation needs its numeric id;
- optional live AI configuration `AI_PROVIDER=openai-compatible`, `AI_API_URL`, `AI_API_KEY`, `AI_MODEL` when `LIVE-AI-MINIMUM-REMEDIATION` is expected to run; with `AI_PROVIDER=disabled` that scenario must remain `NOT_RUN`;
- synthetic `SECURITY_API_KEY`, `SECURITY_API_URL` and `SECURITY_VERIFICATION_URL` only when protected egress/read-back is enabled;
- a synthetic second HTTPS endpoint in `EVIDENCE_DESTINATION_B_URL` only when the destination-binding negative is enabled.

From `t3n-gateway/`:

```bash
npm install
npm run evidence:live
```

The orchestrator:

1. resolves `git rev-parse --verify HEAD` using a fixed-argument child process, requires a full 40-character SHA and records the working-tree state before generated evidence files are written;
2. fails closed on a dirty tree by default; `EVIDENCE_ALLOW_DIRTY_SOURCE=true` is available only for an explicitly non-submission run and records `sourceTreeClean=false` rather than hiding the state;
3. loads the persisted trust-manifest floor for the configured T3N network;
4. authenticates Tenant, Proposal Agent and Protected Executor separately through verified trust anchors using the same monotonic floor;
5. rejects identity collapse and refuses evidence generation unless the sessions report verified trust anchors and a persisted floor;
6. performs read-only public Agent Card verification for the authenticated Proposal Agent DID and records the observed registration state without confusing it with Member Delegation or effective authorization;
7. calculates `SHA-256(WASM_BYTES)`;
8. resolves the configured live contract version or registers it when absent;
9. provisions/read-backs the versioned private T3N operational policy and binds its version/hash;
10. writes sanitized `docs/evidence/deployment-manifest.json` including source revision, trust-anchor, rollback-floor, Agent Card, policy and contract/WASM provenance;
11. optionally prepares the private remediation map when `EVIDENCE_PREPARE_EGRESS=true`;
12. derives least-privilege allowed hosts from the configured HTTPS action/verification endpoints and, only for the controlled destination-binding scenario, the synthetic B endpoint;
13. creates/updates the exact least-privilege Member grants: Proposal only `evaluate-action`, Executor only `execute-remediation` and `verify-remediation`, both with the fixed minimum scopes and no wildcard;
14. calls `checkDelegation()` independently through each authenticated delegated principal for its fixed requirements and fails before scenario execution unless both Member state and effective state are `ACTIVE`;
15. invokes the existing `evidence:testnet` runner. The runner always keeps deterministic T3N policy scenarios separate from the optional live-AI scenario. When the OpenAI-compatible provider is configured it uses the same runtime `OpenAiCompatibleProvider` + `AgentService` for `LIVE-AI-MINIMUM-REMEDIATION`; when AI is disabled the scenario is `NOT_RUN`, not replaced by a fixture;
16. records sanitized Proposal/Executor Member/effective states and exact checked restrictions and writes the same captured source SHA/tree state into `testnet-run.json`;
17. when `EVIDENCE_RUN_DESTINATION_BINDING=true`, requires T3N testnet, independently proves policy ALLOW for distinct hosts A and B, temporarily changes private `security_api_url` from A to B, requires `EXECUTION_DESTINATION_CHANGED` before `hwp::call`, and restores A in `finally`;
18. when `EVIDENCE_RUN_EGRESS_NEGATIVES=true`, revokes Proposal and Executor grants independently, requires direct principal-side `checkDelegation()` to return `authorised=false`, exercises protected rejection where applicable, and restores the known-good minimum grants in `finally`;
19. verifies that testnet evidence and deployment manifest have the same source SHA/tree state, network, SDK, DIDs, contract id/version, WASM hash and policy provenance, and that recorded delegation evidence matches the live positive checks;
20. fails if the runner reports failure, effective delegation is not confirmed, negative revocation/destination evidence fails, source identity is absent/malformed/mismatched, identities mismatch, trust/policy metadata is inconsistent, or leak detection finds configured secret material.

The evidence chain is:

```text
public source revision
   | full Git SHA + CLEAN/DIRTY tree state
   v
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
   +--> exact Member grants -> independent principal-side checkDelegation -> effective access
   v
WASM bytes + canonical policy
   | SHA-256 + policy version/hash
   v
deployment-manifest.json
   | source revision + trust + onboarding + policy + contract + canonical DIDs
   v
T3N testnet runner
   | deterministic T3N scenarios
   | + optional live configured AI proposal -> exact T3N evaluation
   | + sanitized effective-delegation verdicts
   v
testnet-run.json
   | same source revision + live outcomes
```

This closes the linkage `public source -> commit -> WASM/policy identity -> T3N execution -> observed scenarios`. When live AI is configured, `LIVE-AI-MINIMUM-REMEDIATION` additionally links `configured provider/model -> structured proposal -> exact T3N decision`. The source SHA proves which repository revision was captured; the WASM SHA-256 still identifies the binary bytes and the policy hash still identifies the canonical operational policy. A clean source tree is a reproducibility signal, not proof that the source was independently audited. Runtime readiness additionally requires the platform-side delegation verdict described above; the evidence bundle does not infer effective authorization from a Member grant alone. It is not described as hardware attestation unless a separate T3N API explicitly provides execution-specific attestation evidence.

## Live AI minimum-remediation proof

The deterministic `LIVE-MINIMAL-ALLOW` scenario proves the T3N policy result for a known minimum request. It is **not** proof that a real model generated that request.

`LIVE-AI-MINIMUM-REMEDIATION` is separate. When `AI_PROVIDER=openai-compatible`, the runner constructs the same provider and `AgentService` used by the gateway runtime and sends a synthetic minimum remediation prompt that includes the approved host. The returned structured proposal is not rewritten before T3N evaluation.

A `PASS` requires all of the following:

```text
real configured provider invoked
provider + model identified
proposal.action = revoke-credential
proposal.resource = credential:production-security-api
proposal.purpose = incident-remediation
proposal.host = current approved synthetic host
proposal.fields = incident_id + credential_id + reason only
proposal.private_refs = empty
same proposal sent to T3N evaluate-action
T3N decision = ALLOW
```

The evidence detail records only bounded provider/model labels, resource, purpose, canonical host, field/private-reference names, T3N reason code and policy version/hash. It does not persist the prompt, raw provider response, API key, credentials, private values or arbitrary model text.

If `AI_PROVIDER=disabled`, the scenario is `NOT_RUN` with an explicit explanation. If the configured provider fails, returns invalid tool output, proposes another action/field set/host, or T3N returns `DENY`/`REDACT`, the live-AI scenario is `FAIL`. The runner never substitutes the deterministic minimum fixture to manufacture a live-AI `PASS`.

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

Negative grant tests restore the known-good challenge grant in `finally`. They count as PASS only when the expected authorization/delegation rejection is observed; missing private configuration, transport errors or an inconclusive `checkDelegation()` response are FAIL.

## Controlled approved-destination substitution proof

The side-effect hostname approved by the human is a stricter control than the policy host allowlist. The full action URL remains in private T3N KV; the application capability carries only the canonical hostname already persisted in the proposal.

To run the controlled negative, use **synthetic testnet destinations only**:

```bash
SECURITY_API_URL='https://security-a.example/remediate' \
EVIDENCE_DESTINATION_B_URL='https://security-b.example/remediate' \
EVIDENCE_PREPARE_EGRESS=true \
EVIDENCE_RUN_DESTINATION_BINDING=true \
npm run evidence:live
```

The scenario is deliberately rejected when `T3N_NETWORK` is not `testnet`, even if broader evidence execution is explicitly allowed elsewhere. A and B must be different hostnames and both must independently receive policy `ALLOW`; otherwise the scenario is `FAIL` because it would test the allowlist rather than the human-intent binding.

The exact flow is:

```text
proposal host A
  -> T3N policy ALLOW(A)
  -> separately prove T3N policy ALLOW(B)
  -> capability/execute request keeps approved_host=A
  -> private security_api_url temporarily becomes B
  -> Rust compares actualHost(B) to approvedHost(A)
  -> EXECUTION_DESTINATION_CHANGED
  -> BLOCKED_BEFORE_HTTP
  -> restore original security_api_url in finally
```

`PASS` is recorded only when the contract returns the dedicated destination mismatch from the equality guard that is structurally before policy re-evaluation and before `hwp::call`. Any accepted execution or different rejection is `FAIL`. If the environment variables are not enabled, the case remains `NOT_RUN`; documentation or local tests never upgrade it to live proof.

The independent `SECURITY_VERIFICATION_URL` is not substituted into this check. It is a read-back endpoint and may have a different host; `approved_host` binds the execution side effect only.

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

The persistent Business Audit Trail complements that timeline with `AGENT_PROPOSAL_SOURCE`, so a judge can associate each proposal action id with bounded provider/model provenance. A retry can therefore have the same logical incident but a distinct agent-generated action and a distinct policy result without inventing a new incident or application fallback.

A retry can have the same `requestId` and a different `traceId`. This is expected and demonstrates that observability does not alter business idempotency. The Business Audit Trail remains the persistent business history; the Execution Trace explains a technical attempt; the Evidence Bundle remains the reproducible T3N/testnet proof. None substitutes for the others.

The application does not fabricate a Terminal 3 request/receipt identifier. Such an identifier must be displayed or persisted only when the platform API actually returns one.

Execution-trace events are bounded operational metadata, but they are still attached to the incident lifecycle. The incident-retention purge deletes them before the action and incident records so technical correlation cannot outlive the incident's configured retention window.

## Independent T3N Activity Log provenance

The Business Audit Trail and the official T3N Activity Log are separate sources. Local audit records business events such as human authorization; T3N Activity records network-observed contract activity. The application does not replace one with the other or infer a network event solely from a local timestamp.

For an incident, the authenticated backend requests a bounded Activity Log window through the gateway and keeps only events that exactly match the current Tenant DID, resolved contract and one of the supported contract functions (`evaluate-action`, `execute-remediation`, `verify-remediation`). Reconciliation additionally requires the canonical actor for the function: Proposal Agent DID for `evaluate-action`; Protected Executor DID for `execute-remediation` and `verify-remediation`. Sequence, activity hash and function metadata persisted with network-backed local events must also match exactly. The time window only bounds retrieval and includes a clock-skew margin; timestamps are not used as identity.

The API/UI exposes four independent reconciliation states:

- `MATCHED`: the local network-backed event matches the exact T3N sequence/hash/function/actor boundary;
- `LOCAL_ONLY`: the business event has no T3N function by design, for example a purely local step or `AGENT_PROPOSAL_SOURCE`;
- `T3N_ONLY`: a relevant T3N activity event exists without a matching local event in the bounded local result;
- `UNMATCHED`: a local event expects T3N provenance but the exact required metadata/actor could not be verified.

If the Activity Log is temporarily unavailable, local business history remains readable and its HMAC integrity state remains independently reportable, but network-backed local events are shown as unverified/unmatched and the UI states that T3N provenance was not verified. If the bounded Activity Log page is truncated, the response marks it incomplete; unmatched results are not treated as proof that no network event exists. If a canonical Proposal/Executor identity is unavailable, affected events cannot become `MATCHED` merely because the function/sequence/hash are present.

The read-only endpoint is:

```text
GET /api/incidents/{incidentId}/audit-evidence?limit=100
```

The `limit` is server-validated between 1 and 200. The same response keeps `integrity` separate from `provenance`. Activity evidence is sanitized and contains bounded provenance fields such as sequence, hash, actor/on-behalf-of DIDs, contract, function, outcome and timestamp; it never returns T3N keys, audit-integrity keys, capabilities, request bodies or resolved private values. This network provenance remains subject to the incident lifecycle in the application: local incident/audit/trace data are still purged according to retention and are not kept indefinitely merely to preserve a comparison.

## Generated artifacts

`deployment-manifest.json` contains only public/verifiable metadata:

- UTC timestamp;
- full source commit SHA (`sourceCommitSha`);
- explicit source-tree state (`sourceTreeClean`);
- network;
- SDK `5.2.0`;
- canonical Tenant, Proposal Agent and Protected Executor DIDs;
- observed Agent Card registration state;
- Agent Card public URI/SHA-256/verification timestamp/service names when a card was resolved;
- `trustAnchorVerified=true` only after the official signed trust-anchor path succeeds;
- `trustManifestFloorPersisted=true` only after a valid monotonic floor is present on persistent state;
- accepted trust-manifest high-water version;
- canonical and optional numeric contract id;
- contract version;
- policy version/hash;
- WASM SHA-256.

`testnet-run.json` contains the same `sourceCommitSha` and `sourceTreeClean` values plus live scenario outcomes including PASS/FAIL/NOT_RUN and the sanitized delegation evidence for Proposal/Executor. `LIVE-AI-MINIMUM-REMEDIATION` additionally records sanitized provider/model labels and the actual structured proposal metadata inside its scenario detail when a live provider was invoked. Missing, malformed or mismatched source provenance invalidates the bundle. Optional scenarios that were not executed stay `NOT_RUN`; they are never converted into PASS.

Both artifacts pass leak detection against configured Tenant/Proposal Agent/Protected Executor keys, remediation key, AI provider key, service token, capability signing key and optional sentinel before being accepted. Submission-capture metadata additionally treats `AUDIT_INTEGRITY_KEY` as prohibited secret material. Neither artifact contains `.env` contents, API keys, tokens, private keys, audit-integrity key material, prompts, raw provider responses or raw Member Delegation documents.

## Trust, onboarding and authorization evidence wording

The UI and evidence API deliberately distinguish these concepts:

- **Source commit**: full public Git revision captured for the run; it establishes source traceability, not independent verification.
- **Source tree CLEAN/DIRTY**: whether that revision's working tree was clean when evidence generation started; `DIRTY` is disclosed and never relabelled as success.
- **WASM SHA-256**: identity of the contract binary bytes used by the evidence flow.
- **Policy SHA-256**: identity of the canonical operational policy used by the decisions.
- **Trust anchor VERIFIED**: the signed T3N manifest established the cluster trust boundary used by the authenticated sessions.
- **Rollback floor PERSISTED**: the accepted manifest-version high-water mark is stored across gateway restarts and supplied back through `minVersion`.
- **Trust manifest version**: the numeric version exposed by the verified trust anchor and persisted as the high-water mark.
- **Proposal Agent AUTHENTICATED**: the session proved control of its credential and yielded the canonical Proposal Agent DID.
- **Protected Executor AUTHENTICATED**: its independent session proved the separate execution principal DID.
- **Agent onboarding REGISTERED**: a public Agent Card for the Proposal Agent DID resolved and passed the closed validation.
- **Member grant ACTIVE**: the Tenant-side grant record exists and is inside its validity window; this is not yet an effective platform verdict.
- **Effective access ACTIVE**: `checkDelegation()` executed as the authenticated grantee returned `authorised=true` for that principal's canonical contract, Tenant DID and fixed minimum functions/scopes. Only this state may contribute to operational readiness.
- **Effective access DENIED**: `authorised=false`, or a known non-active Member state, prevents readiness.
- **Effective access UNKNOWN**: the Member state or platform verdict could not be validated; readiness remains false.
- **Live AI proposal PASS**: the configured provider/model actually produced the recorded minimum structured proposal and T3N independently returned `ALLOW` for that exact output. Deterministic fixture output or disabled provider cannot satisfy this label.
- **Approved destination**: canonical hostname persisted in the action, evaluated by policy, shown to the operator and signed into the remediation capability. It is narrower than a policy allowlist and must equal the current private execution URL hostname before egress.
- **Destination changed**: the protected action URL resolved to a different hostname after approval. This is a fail-closed authorization mismatch requiring a new evaluation and human authorization, not a generic transport outage.
- **Local audit integrity VERIFIED**: the retained HMAC chain, sequence/linkage and authenticated head validated using configured key versions. This is an application integrity signal, not T3N/hardware attestation.
- **Local audit integrity BROKEN/KEY_MISMATCH/LEGACY_UNVERIFIED**: local history is not eligible for a positive integrity claim; protected local changes fail closed where required.

These labels do not mean “hardware execution verified”. A public Agent Card hash is not authorization or attestation, a clean source tree is not a code audit, and a per-request hardware-attestation claim would require separate execution-specific evidence.

If trust-manifest retrieval, rollback validation, persisted state validation, version extraction or effective-delegation verification fails, readiness remains false. Agent Card resolution has its own explicit negative states (`NOT_REGISTERED`, `MISMATCH`, `UNAVAILABLE`) and is never silently rendered as `REGISTERED`. `authorised=false` produces effective `DENIED`; a failed or malformed platform verdict produces `UNKNOWN`. Local audit verification failure is surfaced independently and is never auto-repaired or relabelled as T3N provenance failure.

## Profile placeholder evidence

The policy-level logical-reference scenario can run independently. Actual `verified_email` profile resolution must remain `NOT_RUN` until a dedicated synthetic T3N profile and compatible user context are available. Unit/integration tests proving the closed mapping do not count as live profile-resolution proof.

## What is not live evidence

Mocks, unit tests, property tests, generated cases, screenshots, docs and unexecuted commands are not T3N testnet proof. A Git commit SHA by itself is not live proof and `CLEAN` is not a security certification; they only link a generated bundle to a source revision. A locally generated Agent Card is not proof that it was hosted; `REGISTERED` requires read-only public resolution of the authenticated DID. An observed Member grant is not proof of effective authority; runtime readiness additionally requires the authenticated principal-side T3N `checkDelegation()` verdict. A deterministic `LIVE-MINIMAL-ALLOW` policy request is not proof that an AI model generated the same proposal. `AI_PROVIDER=disabled` must yield `LIVE-AI-MINIMUM-REMEDIATION = NOT_RUN`, never PASS. The generated deployment manifest plus matching successful `testnet-run.json` are the live evidence source of truth for contract scenarios. A screenshot of a 2xx response is not remediation completion proof; the matching verification state is required. A persisted trust floor is cluster-trust rollback protection, not execution-specific hardware attestation. Activity reconciliation is provenance for T3N-observed operations, not a replacement for local HMAC integrity. Local HMAC integrity is not live T3N proof, immutable storage or hardware attestation.

See `scenario-matrix.md` for the security-scenario mapping.
