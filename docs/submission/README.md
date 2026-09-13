# T3 Privacy Guard - Submission & Judge Guide

## Product position

**T3 Privacy Guard is an enterprise trust runtime for AI agents on Terminal 3.** It does not try to make the model itself an authority. It keeps policy, trusted execution values, identity, private-data resolution, human approval and completion proof outside the model.

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

The challenge implementation uses incident response as the concrete domain, but the trust pattern applies to any enterprise agent that can recommend or trigger sensitive actions.

## Judge-first architecture

```text
Untrusted model
    |
    | structured proposal only
    v
Proposal Agent DID
    |
    | ACTIVE Member grant
    | principal-side checkDelegation() = authorised
    v
T3N Rust/WASM policy
    |
    | DENY / REDACT / ALLOW
    v
Authenticated application operator
    |
    | durable principal + timestamp
    v
Ed25519 v2 one-time authorization proof
    |
    +-----------------------------+
    |                             |
Gateway fail-fast            T3N/WASM proof check
    |                             |
    +-------------+---------------+
                  |
Protected Executor DID
    |
    | ACTIVE Member grant
    | principal-side checkDelegation() = authorised
    v
Protected egress
    |
    v
Independent read-back
    |
    v
VERIFIED -> COMPLETED
```

The important security property is that no single AI-facing component owns all of these authorities.

## What is real in the implementation

### Real model proposal path

When `AI_PROVIDER=openai-compatible`, the gateway sends the textual prompt to the configured provider and accepts only a closed structured proposal surface:

```json
{
  "action": "string",
  "resource": "string",
  "purpose": "string",
  "host": "string|null",
  "fields": ["string"],
  "private_refs": ["verified_email"]
}
```

The model cannot set policy decisions, T3N DIDs, human approval, trusted `normal_payload`, execution proof, API keys or raw profile placeholders.

After a DENY, the application does not manufacture a safe replacement. A follow-up remediation proposal is another real call to the same configured provider in the same incident, persisted as another action and independently evaluated by T3N. Provider failure creates no synthetic fallback action.

### Real T3N identity and delegation separation

Tenant, Proposal Agent and Protected Executor have separate credentials and canonical DIDs obtained from their authenticated T3N sessions.

An observed Member grant is document state, not enough to claim effective authorization. The delegated principal itself must call `checkDelegation()` for the exact contract, tenant `pii_did`, functions and minimum scopes. `authorised=false`, errors and unexpected responses fail closed.

The Proposal Agent is limited to policy evaluation. The Protected Executor is the only delegated principal for protected execution/verification functions.

### Real policy provenance

The Rust policy reads the versioned operational policy from private T3N KV. Every decision carries exact `policyVersion` and `policyHash`. Protected execution rechecks that provenance instead of trusting a stale application decision.

### Real trusted normal-value separation

The model chooses normal field names only. Spring owns the current synthetic operational values, persists the exact map with the action and binds it through `normalPayloadHash` in the authorization proof.

Rust constructs protected egress only from:

```text
persisted trusted values ∩ policy allowed_fields
```

A REDACT decision can continue only when the required minimum survives and the minimized set independently evaluates as ALLOW.

### Real human authorization provenance

`POST /authorize-remediation` derives the approver from the authenticated Spring `SecurityContext`. The browser cannot submit `authorizedBy`.

The action persists:

```text
remediationAuthorizedBy
remediationAuthorizedAt
```

The first valid approval is durable. Same-operator retry is idempotent. A different operator cannot silently replace the original approver. Legacy authorized rows without provenance remain blocked as `REAUTHORIZATION REQUIRED`.

The local audit event contains the sanitized application principal and is covered by the existing HMAC integrity chain. That account is not represented as a civil identity or T3N DID.

## WASM-enforced human authorization proof

This is the protected-execution boundary introduced for issue #128.

### Proof format

Spring signs an explicit v2 Ed25519 proof:

```text
v2.<base64url canonical claims>.<Ed25519 signature>
```

The claims bind:

```text
keyId
incidentId
actionId
requestId
decisionId
action
resource
purpose
approvedHost
fieldsHash
normalPayloadHash
privateRefsHash
policyVersion
policyHash
executorDid
operatorPrincipalHash
authorizedAt
issuedAt
expiresAt
nonce
```

`operatorPrincipalHash` is SHA-256 of the persisted canonical application principal. The username itself is not sent to T3N.

### Key boundary

The backend receives the Ed25519 PKCS#8 private key through `REMEDIATION_AUTH_PRIVATE_KEY_PKCS8`.

The gateway receives only the matching SPKI public key through `REMEDIATION_AUTH_PUBLIC_KEY_SPKI` and the active version through `REMEDIATION_AUTH_KEY_ID`.

The T3N setup script provisions only the versioned public key into contract-restricted private KV:

```text
remediation_auth_public_key_spki:<keyId>
```

The backend private signing key is never provisioned to T3N, Agent Card, browser, gateway response or public evidence.

### Independent contract verification

The gateway validates the proof to fail early, including exact equality with the backend request and persisted human provenance. This is defense in depth, not the final authority.

The same proof is forwarded to `execute-remediation`.

Before Rust reads the protected egress URL/key or performs HTTP, the WASM:

1. bounds and parses the v2 proof;
2. validates the signed `keyId` syntax;
3. resolves `remediation_auth_public_key_spki:<keyId>` from private T3N KV;
4. verifies the Ed25519 signature;
5. validates `authorizedAt`, `issuedAt`, expiry and maximum lifetime;
6. validates action/request/decision/policy/destination/payload/private-reference/Executor bindings;
7. validates the signed human-provenance hash format;
8. hashes and consumes the nonce in the private contract-only replay map;
9. only then continues to current-policy checks, protected secrets and HTTP.

A Protected Executor credential alone therefore does not satisfy the side-effect preconditions.

### Anti-replay

The gateway keeps a persistent local nonce-hash cache for fail-fast behavior. That cache is not the security claim for direct T3N calls.

The WASM separately persists only SHA-256(nonce) plus expiry metadata in:

```text
privacy-guard-execution-nonces
```

The raw nonce and complete proof are not stored as replay state.

Because the available KV interface exposes get/put/delete rather than an explicit compare-and-swap primitive, the project claims deterministic replay rejection for the implemented contract state machine and test coverage, not a generic external-provider exactly-once guarantee.

### Versioned rotation

`keyId` is signed. A new signing key uses a new ID and a separately provisioned public key entry. Previous public keys are not silently substituted for the signed key ID. Any deliberate overlap must be bounded to the short lifetime of already-issued proofs.

Legacy v1/HMAC proof formats are not accepted by protected execution after this migration.

## Exact destination binding

Policy-allowed host and human-approved host are separate concepts.

The operator approves the exact canonical hostname present on the persisted action. That hostname is signed into the proof. The full action URL remains private in T3N KV.

At execution time Rust resolves the current private URL and requires exact hostname equality before HTTP. Approval for A cannot be reused after configuration changes to B, even if both hosts are policy-allowed.

## Private data boundary

The supported logical reference is currently:

```text
verified_email
```

Rust owns the closed mapping to:

```text
{{profile.verified_contacts.email.value}}
```

The model/browser/Spring/normal gateway APIs carry the logical reference, not the resolved e-mail address. This submission does not treat local mapping tests as live profile-resolution evidence. Live profile evidence remains NOT_RUN until a compatible T3N test user/profile context actually executes the protected flow.

## Completion boundary

For the current complete credential-revocation executor, external HTTP acceptance is not final success.

```text
EXECUTING
   |
   v
PENDING_VERIFICATION
   |
   | independent verify-remediation read-back
   +-------------------------+
   |                         |
   v                         v
COMPLETED                UNVERIFIED
```

`COMPLETED` requires read-back of the same operation and the closed expected external state `REVOKED`.

The stable application `requestId` is propagated as idempotency metadata, but the project does not claim external-provider exactly-once unless that provider independently guarantees it.

## Local audit integrity

Business audit events are stored in a versioned HMAC-SHA-256 chain with an authenticated per-incident head.

This proves tamper evidence for retained local audit state when the audit key remains uncompromised. It is not immutable storage, hardware attestation or T3N execution proof.

Important states:

```text
VERIFIED
BROKEN
KEY_MISMATCH
LEGACY_UNVERIFIED
```

`AUDIT_INTEGRITY_KEY` must remain distinct from T3N credentials, service token, operator credentials and the Ed25519 remediation signing key.

## Public discoverability is not authorization

A T3N Agent Card proves only the public discoverability state observed for the Proposal Agent DID. `REGISTERED` is not delegation, policy approval or execution authority.

If `A2A_PUBLIC_URL` is configured, the public A2A endpoint exposes evaluation only. It never exposes human authorization, one-time proofs, trusted normal values, private execution credentials or protected remediation.

## Current action coverage

| Action | Policy evaluation | Protected execution + independent verification |
|---|---:|---:|
| `revoke-credential` | yes | yes |
| `isolate-account` | yes | no |
| `create-incident` | yes | no |
| `notify-security` | yes | not yet in this revision |

`notify-security` already supports the logical `verified_email` policy/private-reference path. A complete placeholder-based protected notification executor with independent delivery verification is tracked separately and must not be claimed by the #128 implementation.

## Evidence model

Local tests prove invariants. Live evidence proves only what was actually observed on T3N testnet. `NOT_RUN` is never PASS.

### Dedicated human-proof adversarial scenario

`t3n-gateway/src/scripts/human-proof-testnet.ts` implements:

```text
Authenticated Protected Executor
  + Member grant ACTIVE
  + Effective access CONFIRMED
        |
        v
direct T3N execute-remediation call
without one-time human proof
        |
        v
expected: T3N/WASM rejection before protected egress
```

Run from `t3n-gateway/`:

```bash
npm run evidence:human-proof
```

The scenario emits only sanitized contract/network status, Executor DID/delegation state and the SHA-256 fingerprint of the public verification key. It does not emit private key material, proof, raw nonce, operator hash or trusted execution values.

This repository change adds the scenario code. Until it is actually executed against a configured T3N testnet deployment, it is **NOT RUN** and must not be presented to a judge as observed live proof.

### Other evidence rules

- source commit/tree identity is reproducibility metadata, not independent audit;
- Agent Card resolution is discoverability evidence, not authorization;
- Member grant state and effective `checkDelegation` are reported separately;
- a local unit test cannot become a live T3N PASS;
- a 2xx cannot become a verified business completion without read-back;
- public evidence may contain public-key fingerprints, never private signing material;
- operator username/e-mail/hash is not exported into the public evidence bundle.

See [../evidence/README.md](../evidence/README.md) and [../evidence/scenario-matrix.md](../evidence/scenario-matrix.md).

## Judge questions this implementation is designed to answer

### Can the model bypass policy?

No model-controlled decision/override surface exists. The policy decision comes from Rust/WASM and protected execution rechecks the approved policy provenance.

### Can the model choose the trusted execution values?

No. Normal values are materialized by Spring from a closed trusted demonstration context and bound by hash.

### Can the model or browser claim who authorized execution?

No. The authorizer comes from the authenticated Spring session and is durably persisted.

### Is the human approval enforced only by the application gateway?

No. The v2 Ed25519 proof is forwarded into T3N and verified by the WASM before egress.

### Is possession of the Protected Executor credential enough for the side effect?

No under the implemented contract path. `execute-remediation` requires both Executor authority and a valid one-time authorization proof.

### Can approval for destination A be used after the private endpoint changes to B?

No. The canonical approved hostname is signed and rechecked against the current private URL before HTTP.

### Does HTTP 2xx mean success?

No. It means acceptance. `COMPLETED` requires independent read-back.

### Does the system prove civil identity of the approving human?

No. It proves provenance of the authenticated application principal captured by Spring and bound into a backend-signed proof.

### Is this per-request hardware attestation?

No. T3N trust/contract execution and the signed proof are distinct claims. The UI/docs do not relabel them as generic hardware attestation.

## Runtime secrets and public material

Private runtime material includes:

```text
T3N_API_KEY
T3N_AGENT_API_KEY
T3N_EXECUTOR_API_KEY
GATEWAY_SERVICE_TOKEN
REMEDIATION_AUTH_PRIVATE_KEY_PKCS8
AUDIT_INTEGRITY_KEY
OPERATOR_PASSWORD
AI_API_KEY
SECURITY_API_KEY
```

Public/non-secret verification material may include:

```text
REMEDIATION_AUTH_PUBLIC_KEY_SPKI
REMEDIATION_AUTH_KEY_ID
public-key fingerprint
policy version/hash
canonical public DIDs
public Agent Card metadata
```

`.env.example` is only a variable-name template and must never contain real credentials.

## Reproduction

Local regression tests:

```bash
bash scripts/run-local-evidence.sh
```

Direct project builds:

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm test && npm run typecheck && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

T3N evidence commands are documented in [../evidence/README.md](../evidence/README.md).

## Submission claim boundary

The strongest defensible current claim is:

```text
T3N identity
+ least-privilege delegated authority
+ independent Rust/WASM policy
+ durable authenticated human provenance
+ Ed25519 signed human-intent proof verified inside execute-remediation
+ T3N-side replay state
+ exact destination and trusted-payload binding
+ Protected Executor separation
+ independent external read-back
```

The repository should be judged on that implemented separation of authority, not on claims that are not observed. Unexecuted live scenarios, unresolved profile plaintext, civil-human identity and external-provider exactly-once semantics remain outside the claim boundary.
