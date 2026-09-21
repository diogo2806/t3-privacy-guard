# T3 Privacy Guard

**Use AI agents in sensitive workflows without handing security authority to the model.**

T3 Privacy Guard keeps private data, policy decisions, business authorization, protected execution and verified completion outside the model while preserving useful AI recommendations. The product is designed for a simple enterprise assumption: **the AI model can be useful and still be untrusted**. The model may analyze an incident and propose an action, but it is not allowed to become the authority that decides policy, selects trusted identities, retrieves private profile values directly, or declares a critical side effect completed.

The product separates those responsibilities across independent controls:

```text
Untrusted AI
    |
    | proposes
    v
Proposal Agent effective T3N access
    |
    v
T3N policy / Rust WASM
    |
    | DENY / REDACT / ALLOW
    v
Human authorization
    |
    | approves business intent + exact destination + Protected Executor DID
    v
One-time execution capability
    |
    v
Protected Executor effective T3N access
    |
    v
T3N protected execution
    |
    v
Independent external read-back
    |
    v
VERIFIED -> COMPLETED
```

The mechanism behind that product value is:

> **AI can propose. Policy decides. Humans authorize. T3N executes. Independent evidence proves the outcome.**

> **Judge / submission guide:** [`docs/submission/README.md`](docs/submission/README.md)  
> **Evidence reproduction:** [`docs/evidence/README.md`](docs/evidence/README.md)  
> **Adversarial matrix:** [`docs/evidence/scenario-matrix.md`](docs/evidence/scenario-matrix.md)

## Executive demo in one viewport

The dashboard has three deliberately separate presentation levels. **Protection flow** is the operational surface where analysis, human authorization, execution and read-back happen. **Executive demo** is a read-only projection of that same runtime state for a judge or enterprise stakeholder. **Evidence** remains the detailed proof surface. The Executive demo does not own a second incident, policy decision, authorization, remediation state machine or evidence source and exposes no Analyze, Authorize, Execute or Verify action.

At 1440×900 the Executive demo uses a value-first reading order: business problem and observable result come before the authority mechanism, while the same conservative runtime facts remain visible.

```text
Use AI agents in sensitive workflows without giving the model security authority
                                  [READINESS]

Business risk                 Observed outcome
        \                         /
         Measured control impact
                    |
          How the control works
AI proposal -> T3N policy -> Human -> Executor -> Verify
                    |
           Proof at a glance
```

The technical thesis `AI can propose. Policy decides. Humans authorize. T3N executes.` remains visible inside the Trust path as the explanation of **how** the control works rather than as the first thing a stakeholder must decode. Its claim semantics remain conservative. Before analysis the result is `NOT YET OBSERVED`. `DENY` becomes `BLOCKED BEFORE PROTECTED EGRESS`; `REDACT` becomes `MINIMIZATION REQUIRED`; `ALLOW` without a human approval becomes `HUMAN AUTHORIZATION REQUIRED`; approval without a side effect becomes `AUTHORIZED / NOT EXECUTED` and verification remains `NOT VERIFIED YET`; `PENDING_VERIFICATION`, `UNVERIFIED` and `FAILED` never become successful outcomes. Only `COMPLETED` after independent read-back may become `VERIFIED EXTERNAL STATE`.

`Proof at a glance` is populated only from an actual `T3N_TESTNET` EvidenceBundle with a full 40-character source commit and observed network/contract metadata. `T3N LIVE / READY` additionally requires protected-remediation readiness and zero evidence failures. `NOT_RUN` stays visible and never counts as proof. Source-tree state, Proposal/Executor DID separation, effective delegation and Agent Card registration are shown as distinct facts rather than being collapsed into a generic “verified” badge. If evidence is absent, the view says `Live evidence not loaded/generated` instead of inventing PASS, LIVE or source provenance.

The submission capture keeps the existing full-page technical screenshots and adds 1440×900 viewport frames for the value-first executive story: value headline, business risk, observed outcome, measured control impact, authority mechanism, initial risk, observed DENY, human authorization without execution, verified outcome when a real read-back exists (or an explicit not-verified frame when it does not), and compact proof. The capture continues to require real testnet evidence, zero FAIL, distinct DIDs and the existing secret-leak detector.

## Business outcome in 60 seconds

The Protection flow translates the same observed runtime state into a judge-first **Business Outcome** summary before the technical panels. Scenario metadata supplies only presentation context such as **Business risk**, **Protected asset**, **Business outcome** and **Success definition**. Policy decisions, requested field/private-reference counts, authorization state, approved destination, remediation state, verification attempts and final state come from the existing incident/action/decision/remediation APIs.

The summary never fills future state or estimates a result. Before an observation it says `Not yet observed`; before an independently verified completion it says `Not verified yet`. `DENY` means the observed proposal was blocked before protected egress. `REDACT` means a smaller scope is required. `ALLOW` is permission to continue, not human authorization or execution. `PENDING_VERIFICATION`, `UNVERIFIED` and `FAILED` are never displayed as successful remediation. `REVOKED — VERIFIED` is shown only after verified credential-revocation read-back; `DELIVERED — VERIFIED` is shown only after `notify-security` read-back confirms both `DELIVERED` and `recipient_resolved=true`.

The only displayed time metrics are calculated from timestamps already emitted by the system:

```text
Time to policy decision = decision.evaluatedAt - action.createdAt
Time to verified outcome = remediation.completedAt - action.createdAt
                           only when state == COMPLETED and completedAt exists
```

Durations below one second are shown as integer milliseconds, durations from one through sixty seconds as seconds with one decimal place, and longer durations as minutes plus seconds. The dashboard does **not** calculate money saved, breach cost avoided, risk-reduction percentages, SLA compliance or ROI because those quantities are not measured by this runtime.

Business Outcome intentionally keeps **Requested field names**, **Policy-allowed field names** and **Policy-redacted field names** as schema-level counts. Value-level minimization is proved separately in the protected-remediation panel and evidence path, where trusted synthetic values are bound, filtered and serialized. Human-principal identity/timestamp is likewise not invented when it is absent from the API. The exact `Approved destination` is shown as human-approved only after the persisted action state proves authorization.

## Operational incident workspace

Protection flow includes an authenticated **Incident workspace** that turns the retained incident set into an operational queue instead of treating only the newest case as usable. `GET /api/incident-workspace` returns every incident still inside the server-side retention window together with a server-derived summary of the latest proposal, policy decision, remediation state, operational stage and next required action. The service performs batch reads for proposals, decisions and remediations so the browser does not build the queue through one request per incident.

The workspace is navigation, not a second workflow engine. Selecting a row loads that incident's existing proposals, decision, remediation, execution trace and audit history. Selection never authorizes, executes or verifies anything. The mutation buttons remain only in their existing responsible components and continue to be protected by the backend authority matrix.

Operational stage truth is conservative:

```text
no proposal                     -> NEEDS_ANALYSIS
proposal PENDING                -> POLICY_EVALUATION_REQUIRED
DENY                            -> POLICY_BLOCKED
protected ALLOW/REDACT          -> HUMAN_APPROVAL_REQUIRED
REMEDIATION_AUTHORIZED          -> AUTHORIZED_EXECUTION_PENDING
EXECUTING                       -> EXECUTION_IN_PROGRESS
PENDING_VERIFICATION            -> VERIFICATION_PENDING
COMPLETED                       -> VERIFIED_COMPLETE
UNVERIFIED                      -> UNVERIFIED_REVIEW_REQUIRED
FAILED                          -> FAILED_REVIEW_REQUIRED
unprovable/inconsistent state   -> STATE_UNAVAILABLE
```

Only persisted `COMPLETED` is presented as verified completion. `ALLOW` is not authorization, `REMEDIATION_AUTHORIZED` is not execution, and `PENDING_VERIFICATION` is not success. A stale incident that expires between queue retrieval and opening is removed after a 404 instead of being kept by browser cache.

Rapid incident switching is guarded by a selection generation token. Responses belonging to an older selection are discarded, and the previous incident's decision, remediation, trace and audit state are cleared before the newly selected detail is loaded. This prevents a slow request from making data from incident A appear under incident B.

Demo scenario metadata remains intentionally separate from persisted incident identity. When an incident is resumed from the operational workspace and no persisted scenario binding exists, Business Outcome and Executive Demo do not infer the currently selected demo scenario from title or position. They show the selected incident's runtime facts and explicitly state that demo-only business metadata is unavailable rather than attributing another scenario's risk/asset/outcome to the case.

The queue's empty state is actionable (`No active incidents. Run a scenario or wait for a new incident to start a protected decision flow.`), list/detail failures expose retry actions, and the Screen Manual documents selection, states, permissions, retention, fast-switch behavior and the demo-versus-persisted context boundary. Queue styling remains in `frontend/src/shared/styles` and the component lives under `frontend/src/components/incidents`.

## Value-level normal payload minimization

The model may select normal **field names**, but it never supplies the values used by protected execution. Spring materializes supported synthetic values from a closed server-owned table, rejects secret/unknown keys from becoming trusted values, and persists the exact `normalPayload` with the action. `normal_payload`/`normalPayload` are rejected on the model/A2A proposal surface.

Before execution, the human capability binds the trusted map through `normalPayloadHash`. Java and TypeScript use the same deterministic UTF-8 representation with ASCII-lexically sorted canonical keys:

```text
<keyByteLength>:<key>=<valueByteLength>:<value>\n
```

Changing any key or value after authorization becomes `CAPABILITY_BODY_MISMATCH` before T3N execution.

Inside `execute-remediation`, Rust re-reads the exact approved policy version/hash, validates the trusted map, evaluates the requested field names, then constructs the external body from the exact intersection `normal_payload ∩ allowed_fields`. Credential revocation requires `incident_id`, `credential_id` and `reason`; security notification requires `incident_id`, `severity` and `summary` plus exactly the logical private reference `verified_email`. The minimized field set is evaluated again and must become `ALLOW` before `hwp::call`. A requested extra non-secret field can therefore produce `REDACT` while the protected executor sends only the action-specific executable minimum.

```text
trusted persisted values
  incident_id          = inc-demo-001
  credential_id        = cred-demo-001
  reason               = suspected compromise
  employee_department  = finance
            |
AI requests field names only
            |
T3N policy -> REDACT employee_department
            |
capability binds normalPayloadHash
            |
Rust builds exact allowed subset
            |
protected HTTP body
  incident_id
  credential_id
  reason
```
Private profile values remain structurally separate. For `notify-security`, `verified_email` is the only supported logical private reference. The raw `{{profile.verified_contacts.email.value}}` marker is created only inside Rust/WASM after policy, destination and one-time human-authorization checks; it is never copied into `normal_payload`, React, Spring, the model or normal gateway responses.

The optional `LIVE-NORMAL-PAYLOAD-MINIMIZATION` testnet scenario uses synthetic sentinels and accepts PASS only when controlled read-back reports `must_egress_seen=true` and `must_not_egress_seen=false`. The raw sentinel strings are not persisted in the public evidence bundle. Until that scenario is actually run, its status remains `NOT_RUN` and is not live proof.

## What problem it solves

Enterprise agents are often given enough context and credentials to be useful. That creates a dangerous coupling: a prompt injection, compromised model or bad instruction can become data access or a real side effect if the same component is also trusted to authorize what it proposes.

T3 Privacy Guard breaks that coupling. The AI receives a deliberately narrow proposal surface. Security-sensitive authority is derived elsewhere and cannot be supplied by the model.

For T3N authorization, the system also separates what is configured from what the platform actually authorizes. An `ACTIVE` Member grant is document state only. The authenticated Proposal Agent and Protected Executor must each call `checkDelegation` for the exact contract, canonical tenant `pii_did`, functions and minimum scopes required by that principal. `authorised=false`, an exception or an unexpected response fails closed and cannot be rendered as operational readiness.

For private profile data, the application carries logical references such as `verified_email`, not the private value. The Rust/WASM contract maps a closed reference to the supported T3N profile marker only inside the protected execution boundary. React, Spring Boot, the model and normal gateway responses do not receive the resolved plaintext.

For side effects, an HTTP success response is not treated as business completion. The application records `COMPLETED` only after a separate read-back observes the action-specific closed external state. Notification completion additionally requires the external verifier to report `recipient_resolved=true` without returning the recipient value.

## Where it applies

The current implementation is demonstrated through security incident response, but the trust pattern is broader. The same architecture is relevant anywhere an AI agent can recommend or trigger actions involving sensitive data or privileged operations, for example:

- security operations, where an agent can propose credential revocation, account isolation, incident recording or a security notification;
- HR or identity workflows, where an agent may need a verified attribute but should not receive the underlying private value;
- financial or compliance workflows, where policy and human authorization must remain independent from the model;
- support and operations agents, where outbound destinations and fields must be restricted to an explicit minimum;
- autonomous enterprise agents, where a useful model must not implicitly become the source of authorization.

The project does **not** claim that all of those vertical workflows are already implemented. They illustrate where the trust-runtime pattern can be applied.

## 60-second mental model

A judge should be able to understand the system through two opposite scenarios.

### 1. Compromised-agent scenario

```text
Prompt injection
   |
   v
AI proposes:
- send api_key
- attacker.example
   |
   v
Proposal Agent Member grant ACTIVE
+ effective T3N access CONFIRMED
   |
   v
T3N Rust/WASM policy
   |
   v
DENY

No protected egress.
No model-controlled override.
```

### 2. Legitimate-remediation scenario

```text
AI proposes minimum valid action + destination A
   |
   v
Proposal effective access CONFIRMED
   |
   v
T3N policy -> ALLOW / executable REDACT minimum
   |
   v
Authenticated human authorizes exact action + destination A
   |
   v
Short-lived one-time capability
bound to destination A + trusted normal-payload hash + Protected Executor DID
   |
   v
Executor effective access CONFIRMED
   |
   v
KV-resolved execution host must still equal destination A
   |
   v
Current T3N policy + minimized payload re-check
   |
   v
Protected T3N execution
   |
   v
PENDING_VERIFICATION
   |
   v
Independent external read-back
   |
   +--> expected state observed -> COMPLETED
   +--> ambiguous/mismatch      -> UNVERIFIED
```

For `revoke-credential`, the expected state is `REVOKED`. For `notify-security`, it is `DELIVERED` plus `recipient_resolved=true`. This is why `ALLOW` is not the same thing as execution, an observed grant is not the same thing as effective authorization, a policy-allowed destination is not automatically the human-approved destination, a `REDACT` field-name decision is not by itself proof of value-level filtering, and HTTP `2xx` is not the same thing as completion.

## What the demo proves

T3 Privacy Guard assumes the AI agent can be manipulated. The dashboard sends an actual textual prompt to a configured tool-calling model. The model can produce an unsafe structured proposal such as `host=attacker.example` plus `api_key`, but it cannot set a decision, identity, capability, trusted normal payload or secret. That proposal is persisted and evaluated independently by the T3N Rust/WASM policy, which returns `DENY`.

The Proposal Agent uses its own authenticated T3N credential/DID and is restricted to `evaluate-action`. Before evaluation is considered ready, the gateway requires both an active Proposal Member grant and a principal-side `checkDelegation` result with `authorised=true` for the exact contract, tenant DID and minimum scopes. The tenant session is never used as a substitute for that delegated-principal check.

For executable credential revocation, Spring persists trusted synthetic normal values independently from the model-selected field names. A legitimate policy result may be `ALLOW`, or `REDACT` when an unnecessary non-secret field was requested. `REDACT` can continue only if all required revocation fields survive, and the T3N contract re-evaluates the resulting minimum set as `ALLOW` before HTTP. The same protected executor now has a separate closed `notify-security` branch requiring `incident-notification`, the three notification normal fields and exactly `private_refs=["verified_email"]`.

An authenticated operator must explicitly authorize remediation. Immediately before execution the Spring backend signs a short-lived, one-time capability bound to the exact persisted action, decision, canonical approved hostname, requested fields, `normalPayloadHash`, logical private-data references, exact policy version/hash and authenticated Protected Executor DID. The Executor uses a separate T3N credential/DID and its own least-privilege Member grant for `execute-remediation` + `verify-remediation`. Its fixed delegation scope includes the revocation minimum plus `verified_contacts.email.value`, while the Proposal Agent remains evaluation-only. Protected remediation is considered ready only when the Executor's principal-side `checkDelegation` returns `authorised=true` for the exact restrictions. The gateway validates service authentication, signature, expiry, body equality including `approved_host` and the normal-payload hash, and replay state before T3N execution.

The full action URL remains only in the private T3N KV. Inside `execute-remediation`, Rust extracts the current hostname and requires exact canonical equality with the hostname approved by the operator **before policy re-evaluation and before HTTP egress**. A different destination returns `EXECUTION_DESTINATION_CHANGED`; even if both A and B are allowed by policy, approval for A cannot be reused for B. The contract then re-checks current policy provenance and builds the outbound normal payload only from trusted persisted values whose keys survive the policy.

Private profile values are structural to T3N. The agent, React, Spring Boot and gateway APIs carry only the logical `verified_email` reference. Only Rust/WASM maps that closed reference to `{{profile.verified_contacts.email.value}}`, and T3N resolves the plaintext during protected egress. The resolved value is never returned to the application. Upstream execution responses are reduced to bounded operation metadata, and `operation_id` must itself be a safe opaque ASCII identifier so reflected e-mail/plaintext cannot be smuggled back as metadata.

A successful external HTTP response is **not** treated as completion. The backend first acquires a durable execution claim, the contract propagates the stable `requestId` as an idempotency key, accepted egress becomes `PENDING_VERIFICATION`, and a separate `verify-remediation` read-back must observe the closed expected state before Spring records `COMPLETED`. `notify-security` additionally requires `recipient_resolved=true`. Ambiguous outcomes are `UNVERIFIED` and are never automatically re-executed.

## Architecture

```text
Untrusted prompt
      |
      v
Configured AI provider
      | action + requested field names + logical private refs only
      v
React / Spring Boot
      | trusted synthetic normal values persisted separately
      v
Node / TypeScript T3N Gateway
      | capability verifies normalPayloadHash
      +--> authenticated Proposal Agent DID + tenant pii_did
      |       | Member grant ACTIVE
      |       | checkDelegation(evaluate-action + exact scopes) = authorised
      |       v
      |    T3N / Rust WASM policy
      |       DENY | REDACT | ALLOW
      |                        |
      |                  human authorization
      |                  exact approved destination
      |                        |
      |                  one-time capability
      |                  bound to payload hash + destination + Executor DID
      |                        |
      +--> authenticated Protected Executor DID
              | Member grant ACTIVE
              | checkDelegation(execute-remediation + verify-remediation + exact scopes) = authorised
              v
        private KV URL -> exact approved-host equality
              |
        current policy re-check
              |
        trusted payload ∩ allowed_fields -> re-evaluate minimum
              |
        notify-security only: Rust creates verified_email profile marker
              |
        protected execution in T3N
              |
        PENDING_VERIFICATION
              |
        independent T3N read-back
              |
        VERIFIED -> COMPLETED
        otherwise -> UNVERIFIED
```

- `frontend/`: React/Vite operator dashboard served by Nginx.
- `backend/`: Java 21/Spring Boot business API, operator sessions and durable business/remediation state.
- `t3n-gateway/`: isolated T3N SDK adapter, AI provider adapter, separate tenant/Proposal/Executor sessions, effective-delegation verification and anti-replay protection.
- `contracts/privacy-guard/`: Rust/WIT policy, normal-payload minimization, closed private-reference mapping, protected remediation and independent verification for `wasm32-wasip2`.

Each runtime has its own Dockerfile. There is intentionally no `docker-compose.yml`; services are deployed independently in containers.

## Authority separation

The architecture deliberately prevents the model from owning security authority.

| Responsibility | Authority |
|---|---|
| Understand prompt and propose an action / requested field names | AI model |
| Materialize trusted normal demonstration values | Spring application context |
| Authenticate tenant, Proposal Agent and Protected Executor identities | Separate T3N sessions |
| Observe configured Member grants | Tenant Member Delegation read-back |
| Prove effective delegated access for exact functions/scopes | Principal-side T3N `checkDelegation` |
| Publish/resolve public agent discoverability | T3N Agent Card registry |
| Decide allowed action/data/host | Rust/WASM policy + versioned private T3N KV policy |
| Construct exact outbound normal-value subset | Rust/WASM protected executor |
| Approve business remediation and exact execution destination | Authenticated operator |
| Prove an exact approved execution | Short-lived one-time capability bound to canonical destination + trusted normal-payload hash + Protected Executor DID |
| Resolve approved private profile value | T3N protected execution boundary |
| Decide whether external side effect is complete | Independent read-back + Spring state machine |

The prompt is untrusted content. It is never an authorization or trusted-value source.

## Real AI agent boundary

The gateway supports an optional OpenAI-compatible tool-calling provider through:

```text
AI_PROVIDER=openai-compatible
AI_API_URL=<provider chat-completions endpoint>
AI_API_KEY=<runtime secret>
AI_MODEL=<tool-calling model>
```

`AI_PROVIDER=disabled` is the safe default. When disabled or unavailable, agent analysis fails closed; no fixture is promoted as live AI.

The only model tool surface is:

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

Unknown properties are rejected. In particular the model cannot supply `decision`, `allow`, `override`, `approved`, `agent_did`, `pii_did`, `normal_payload`, `normalPayload`, API keys, credentials, secrets, remediation capabilities or literal `{{profile...}}` markers. `agent_did` comes only from the authenticated Proposal Agent session, the Protected Executor DID comes only from its authenticated session, `pii_did` only from the authenticated tenant session, and normal values only from the trusted application-side factory.

Real private values must never be placed in demo prompts; the model asks only for an enumerated logical category when a supported private value is needed.

Before a prompt reaches a configured remote AI provider, the gateway runs a deliberately **partial high-confidence sensitive-literal guard**. It blocks supported structured classes that can be validated defensibly: e-mail, CPF, checksum-valid CNPJ, strongly signalled phone numbers (E.164 or an explicit phone/mobile/telefone/celular label), public IP addresses explicitly labelled as customer/user data, API keys/tokens, Bearer tokens, JWTs, private-key markers, labelled passwords and Luhn-valid card candidates. Public IPs used as technical URLs/hosts are not blocked merely for being IP literals, and the guard does not attempt generic regex detection of names or addresses.

That boundary reduces the chance of supported literals reaching the provider; it is **not** a semantic or exhaustive PII scanner. A prompt that passes the guard is not certified `PII-free`, `safe` or equivalent. Rejected errors expose categories only, never the matched value or offset. The shared versioned corpus at `privacy-conformance/sensitive-literal-corpus.json` is consumed by both TypeScript gateway tests and Java persistence-boundary tests so the overlapping cases cannot drift silently.

```text
known supported high-confidence literal -> BLOCK BEFORE PROVIDER
other/unstructured free text            -> no absolute PII-free claim
supported private T3N value             -> logical reference such as verified_email
trusted normal execution value          -> server-owned synthetic context, never model output
```

## Public T3N Agent onboarding and discoverability

The Proposal Agent has deliberately separate states: **authenticated**, **registered**, **Member grant**, and **effective access**. Authentication proves control of the configured Proposal credential and yields the canonical Agent DID. Registration proves that a public Agent Card for that same DID can be resolved from T3N. Member Delegation is the tenant/data-owner grant document. Effective access is the independent principal-side T3N authorization verdict for the exact operation. Registration and grant read-back never imply effective access by themselves.

The onboarding/authorization flow is:

```text
separate T3N Proposal Agent credential
        |
        v
authenticated AgentSession
        |
        v
canonical did:t3n:... from the session
        |
        +--> deterministic safe Agent Card
        |          |
        |          v
        |       T3N hosted public card
        |          |
        |          v
        |       REGISTERED / negative onboarding state
        |
        +--> Member grant ACTIVE
                   |
                   v
             checkDelegation
                   |
                   v
       effective access CONFIRMED / DENIED / UNKNOWN
```

`buildAgentCardForSession(...)` uses only `AgentSession.getAgentDid()` as the identity source. The card advertises the EIP-8004 registration type used by the installed T3N tooling, one `DID` service pointing to the same canonical DID, `active: true` and `x402Support: false`. It does not advertise A2A, MCP, x402 payment support or private/internal gateway endpoints that this project does not actually expose. Sensitive metadata keys and private-key-shaped values are rejected, and both generated and resolved cards are bounded by the hosted-card size limit.

Operational commands from `t3n-gateway/`:

```bash
npm run agent:card:verify    # read-only; does not publish or grant permissions
npm run agent:card:publish   # explicit mutable T3N operation; may consume credits
```

The publish command authenticates the Tenant/Admin through the secp256k1 `T3N_API_KEY`, requires the explicit public `T3N_ORG_DID` as the organization owner, authenticates the Proposal Agent separately through `T3N_AGENT_API_KEY`, and obtains the canonical Proposal Agent DID only from `AgentSession.getAgentDid()`. It writes the safe card locally, creates the organization data client from the authenticated Tenant/Admin session, calls `agentCardSet`/`agentCardPublish` with `ownerDid=T3N_ORG_DID` and that authenticated `agentDid`, then performs read-only `AgentCardRegistry.verify()` until the card resolves as `REGISTERED` or fails closed. `T3N_ORG_DID` is public owner identity and must never be derived from `T3N_API_KEY`, `T3N_AGENT_API_KEY`, an Ethereum address or any other secret/key. The publication path does not use a CLI subprocess; `agent:card:verify` remains read-only.

Runtime/evidence states are intentionally precise:

- `REGISTERED`: a valid public card resolved and its DID/service matches the authenticated Proposal Agent DID;
- `NOT_REGISTERED`: the public card endpoint returned no card for the DID;
- `MISMATCH`: a card was returned but failed the closed schema/DID/service validation;
- `UNAVAILABLE`: authenticated DID or public resolution could not be verified at that moment;
- Member grant `ACTIVE`: the observed tenant delegation document has a currently valid grant, but this alone does not prove effective authorization;
- Effective access `CONFIRMED`: the authenticated delegated principal's exact `checkDelegation` returned `authorised=true` while the Member grant is active;
- Effective access `DENIED`: the exact platform check returned `authorised=false`;
- Effective access `UNKNOWN`: the platform check failed or returned an unexpected result.

The dashboard shows onboarding, Member grant and Effective T3N access separately for the Proposal Agent, and Member grant/effective access separately for the Protected Executor. `DENIED` and `UNKNOWN` never use a positive operational state. Evidence may include the public card URI, SHA-256 of the exact resolved card, verification timestamp and declared service names. Those values are public discoverability provenance, not authorization and not hardware attestation.

## Current policy vocabulary

The current Rust policy contains four concrete security actions:

| Action | Purpose | Minimum normal fields | Private reference |
|---|---|---|---|
| `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none |
| `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none |
| `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none |
| `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | exactly `verified_email` for protected execution |

Extra non-secret fields are minimized with `REDACT`. For protected `revoke-credential` and `notify-security`, a REDACT decision may continue only when the action-specific required normal fields survive and the minimized set re-evaluates to `ALLOW`; removed keys are not serialized. `notify-security` additionally requires `verified_email` to remain policy-allowed. Forbidden secret fields are denied. Unsupported actions, purposes, hosts or private references fail closed.

## Versioned operational policy in private T3N KV

The mutable operational rule set is no longer hardcoded as application state. Contract `0.4.0` reads a canonical `PolicyDocument` from the private T3N KV map `privacy-guard-policy`. The document controls enabled actions, purpose, allowed hosts, normal field allowlists, supported logical private references, host requirement and whether human authorization is required.

Critical security invariants remain compiled into Rust/WASM and cannot be relaxed by KV configuration. This includes schema/size ceilings, fail-closed behavior, authenticated T3N identity boundaries, forbidden secret classes, trusted-normal-payload validation, the closed private-reference vocabulary and safe host validation. A policy document cannot make `api_key`, passwords, tokens or private keys valid outbound fields and cannot bypass delegation or identity checks.

Every valid policy decision carries:

```text
policyVersion   exact immutable policy version
policyHash      SHA-256 of the canonical policy document
requiresHumanAuthorization
```

The gateway provisioner stores immutable snapshots as `version:<version>`, maintains `current`, and records publication/rollback history. Publishing different canonical content under an existing version is rejected. Rollback is explicit through `T3N_POLICY_ROLLBACK_VERSION` and may target only a version already persisted in the private map. A missing, malformed, oversized or semantically invalid policy fails closed.

Policy provenance follows the decision through Spring persistence, the API, the dashboard, deployment/evidence metadata and the remediation capability. Protected remediation re-reads the active T3N policy and requires the exact version/hash that was approved. The capability additionally binds the trusted normal payload by hash and the exact approved destination. If policy provenance, payload values or destination change after authorization, the old approval cannot be silently reused.

`policyHash` is provenance, not a hardware-attestation claim.

## Enterprise scenario catalog

The Protection demo exposes those four policy actions as business-readable, synthetic presets. Selecting a card only changes local demonstration context and the editable prompt; it does not call an API, authorize anything or predict the T3N result.

| Scenario | Proposed action | What the demo proves |
|---|---|---|
| Credential compromised | `revoke-credential` | Prompt-injection denial plus a separate minimum-scope revocation path with value-level minimization, human authorization, destination binding, protected execution and independent `REVOKED` read-back. |
| Account takeover | `isolate-account` | The model can propose isolation with synthetic identifiers while T3N independently evaluates action, fields, purpose and destination. |
| Record security incident | `create-incident` | Incident recording can be evaluated without outbound egress; adding an unexpected destination remains subject to T3N policy. |
| Notify security contact | `notify-security` | Logical `verified_email` only in app layers, Rust-only profile-marker creation, human-authorized protected egress and independent `DELIVERED + recipient_resolved=true` read-back. |

Protected execution/read-back is implemented for `revoke-credential` and `notify-security`. `isolate-account` and `create-incident` remain genuine policy-evaluation scenarios without a protected side-effect executor. The UI exposes execution controls only when the selected action satisfies the closed contract for one of those implemented executors.

Switching scenarios clears the previous scenario result in the browser before a new analysis. This prevents a prior decision or execution state from being visually attributed to a different preset.

## Structural private-data boundary

The initial private reference is intentionally narrow:

```text
logical reference: verified_email
action/purpose:   notify-security / incident-notification
TEE mapping:       {{profile.verified_contacts.email.value}}
```

The literal marker is created inside Rust/WASM from a closed allowlist. Clients cannot submit arbitrary profile namespaces. `verified_email` on an unrelated action is minimized with `REDACT`; unknown references and literal placeholder strings are denied. Spring persists only the reference name, never the email address. Human authorization capabilities bind the private-reference set so it cannot be changed after approval.

For a private value obtained through this supported logical-reference flow, plaintext visibility is:

```text
AI model                       NO
React / browser                NO
Spring Boot / H2               NO
Node gateway request/response  NO
Business audit/evidence        NO
T3N protected egress           YES, only while resolving the approved placeholder
Allowed external service       YES, as the intended recipient of the protected egress
```
This table does not make a blanket claim about arbitrary user-supplied free text: users must not paste private values into the prompt, and the pre-provider guard is intentionally partial.

`PlaceholderDenied`, `PlaceholderUnknown` and `PlaceholderNoUserContext` fail closed. Upstream responses are reduced to bounded operation/status metadata before leaving the contract. The accepted `operation_id` syntax is limited to an opaque 1–128 byte ASCII alphanumeric/`-`/`_` identifier; an e-mail or other reflected value containing characters outside that grammar is discarded instead of crossing the protected boundary.

## Distributed remediation boundary

The persistent state machine is:

```text
REMEDIATION_AUTHORIZED
        |
        | pessimistic atomic claim
        v
EXECUTING
        |
        | destination equality + current policy re-check
        | trusted normal payload ∩ allowed_fields
        | notify-security: verified_email marker created only in Rust/WASM
        | external request with requestId as stable Idempotency-Key
        v
PENDING_VERIFICATION
        |
        | independent verify-remediation read-back
        +----------------------------+
        |                            |
        v                            v
COMPLETED                       UNVERIFIED
```

Rules:

- only one application execution claim can be created per action;
- a fresh concurrent caller observes the existing `EXECUTING` claim instead of sending a second request;
- the canonical hostname approved by the human is signed into the execution capability and must equal the hostname currently resolved from private `security_api_url` before any HTTP call;
- the capability also binds the exact persisted normal payload by `normalPayloadHash`; key/value mutation fails before T3N execution;
- Rust rejects forbidden secret keys, trusted keys that were not requested, missing action-specific required fields and a minimized set that does not re-evaluate to `ALLOW`;
- `notify-security` additionally requires purpose `incident-notification`, exactly `private_refs=["verified_email"]` and policy allowance for that reference;
- `EXECUTION_DESTINATION_CHANGED` is a fail-closed blocked execution, requires a new action/evaluation/authorization and is not retried automatically;
- an execution acknowledgement or any HTTP 2xx is only acceptance, never completion;
- `COMPLETED` requires read-back matching the same safe opaque `operation_id` and the action-specific closed state: `REVOKED` for credential revocation, `DELIVERED` plus `recipient_resolved=true` for security notification;
- a timeout after send, missing/unsafe operation id, mismatched request id, unavailable verification or contradictory read-back becomes `UNVERIFIED`;
- `UNVERIFIED` may be re-verified when a valid operation id exists, but is never automatically re-executed;
- persisted remediation state can be read after reload/restart without causing egress or a verification attempt;
- the project does **not** claim exactly-once/at-most-once behavior from an external provider merely because an idempotency key is supplied. Provider support is required for that guarantee.

## Tamper-evident local audit integrity

Spring stores each sanitized business-audit event in an HMAC-SHA-256 chain scoped to its incident. The versioned canonical payload authenticates the incident/event identifiers, monotonic local sequence, event type, canonical UTC timestamp, sanitized message, persisted T3N sequence/hash/function when present, and the previous event MAC. A separately authenticated per-incident chain head binds the retained tail, so direct content changes, sequence/link changes, inserted rows, missing head and tail deletion are detectable when the verifier runs.

`AUDIT_INTEGRITY_KEY` is a backend-only runtime secret and must remain distinct from T3N credentials, `GATEWAY_SERVICE_TOKEN`, `REMEDIATION_CAPABILITY_KEY` and operator credentials. `AUDIT_INTEGRITY_KEY_ID` identifies the active key version. Planned rotation keeps explicitly versioned historical material in `AUDIT_INTEGRITY_PREVIOUS_KEYS` only while retained events still require it. Events created before this protection remain `LEGACY_UNVERIFIED`; automatic legacy bootstrap is disabled by default instead of inventing historical authenticity.

This control is **tamper-evident, not immutable or tamper-proof**. Its threat model is DB/storage-only modification by an actor that does not possess the HMAC key. A compromise that obtains both database and key, a compromised backend capable of producing valid new MACs, or restoration of a complete older internally consistent database snapshot is outside this claim unless an independent monotonic external anchor is added.

Local audit integrity and T3N Activity Log provenance are independent signals. A local chain may be `BROKEN` while a network event is still `MATCHED`; Activity Log unavailability does not make an otherwise verifiable local chain `BROKEN`. Protected local changes fail closed when the retained chain is not verifiable. Incident retention deletes audit content and its local chain head rather than retaining messages indefinitely just to preserve the chain.

## Security boundaries

- Operator login is an application identity, not a T3N or AI-provider identity.
- `T3N_API_KEY`, `T3N_AGENT_API_KEY`, `T3N_EXECUTOR_API_KEY` and `AI_API_KEY` are gateway-only runtime secrets and are never returned to the browser.
- Proposal Agent and Protected Executor credentials/DIDs are separate from each other and from the tenant.
- `GATEWAY_SERVICE_TOKEN` is a separate service-to-service credential.
- `REMEDIATION_CAPABILITY_KEY` signs one-time human authorization proofs and is distinct from every T3N/provider/remediation credential.
- `AUDIT_INTEGRITY_KEY` is a backend-only HMAC secret, separate from every other credential and never returned by audit APIs or evidence surfaces.
- Canonical tenant/Proposal/Executor DIDs come from authenticated T3N sessions.
- A public Agent Card is discoverability metadata and never grants functions, scopes, hosts or business authorization.
- Delegated calls and `checkDelegation` derive `pii_did` internally from the authenticated tenant session.
- Member Delegation restricts contract, functions, scopes, hosts and validity but is not treated as sufficient proof of effective authorization.
- Effective authorization is confirmed only by principal-side T3N `checkDelegation` for exact least-privilege restrictions; DENIED/UNKNOWN fail closed.
- The model proposes field names; it cannot provide trusted `normal_payload` values, identities, decisions or capabilities.
- Spring owns the bounded trusted synthetic normal values used by the current demo; the capability binds their canonical hash and Rust controls the outbound subset.
- The model/application carry only logical private references; only the contract maps them to supported T3N profile markers.
- exact policy provenance + exact approved destination + trusted payload hash + authenticated operator + explicit human authorization + valid one-time capability + confirmed Protected Executor effective access are required before protected remediation.
- The full action URL, path and credentials are never added to the capability; only the already non-secret canonical hostname from the approved proposal is bound. The private URL remains in T3N KV and must resolve to that same hostname at execution time.
- Consumed capability nonces are persisted at `REMEDIATION_REPLAY_STORE_PATH` so replay protection survives gateway restart when `/data` is persistent.
- Local HMAC integrity is an application tamper-evidence control; it is not T3N execution proof, hardware attestation, immutable storage or a substitute for independent network provenance.

See the threat model and claims matrix in [`docs/submission/README.md`](docs/submission/README.md).

## Runtime configuration

Relevant names include:

```text
T3N_API_KEY
T3N_ORG_DID
T3N_CONTRACT_VERSION
T3N_POLICY_FILE
T3N_AGENT_API_KEY
T3N_EXECUTOR_API_KEY
OPERATOR_USERNAME
OPERATOR_PASSWORD
OPERATOR_SESSION_TIMEOUT
SESSION_COOKIE_SECURE
GATEWAY_SERVICE_TOKEN
REMEDIATION_CAPABILITY_KEY
REMEDIATION_CAPABILITY_TTL_SECONDS
REMEDIATION_REPLAY_STORE_PATH
AUDIT_INTEGRITY_KEY
AUDIT_INTEGRITY_KEY_ID
AUDIT_INTEGRITY_PREVIOUS_KEYS
AUDIT_INTEGRITY_ALLOW_LEGACY_BOOTSTRAP
AI_PROVIDER
AI_API_URL
AI_API_KEY
AI_MODEL
SECURITY_API_KEY
SECURITY_API_URL
SECURITY_VERIFICATION_URL
EVIDENCE_RUN_DESTINATION_BINDING
EVIDENCE_DESTINATION_B_URL
EVIDENCE_RUN_PAYLOAD_MINIMIZATION
EVIDENCE_RUN_PROFILE_PLACEHOLDER
EVIDENCE_NOTIFICATION_AUTHORIZATION_PROOF
```

`T3N_API_KEY` authenticates the Tenant/Admin session used for organization-owned Agent Card publication and other administrative T3N operations. `T3N_ORG_DID` is the canonical public DID of the organization that owns the Proposal Agent; it is explicit configuration and must never be derived from a credential, Ethereum address or other secret. `T3N_AGENT_API_KEY` authenticates the Proposal Agent and must remain separate from the administrative credential.

`T3N_CONTRACT_VERSION` follows the packaged contract artifact; the current packaged contract is `0.4.5`, and EasyPanel should leave this variable unset unless the documented migration procedure explicitly requires otherwise. `T3N_POLICY_FILE` points to the local source document used by the explicit policy provisioning script; the active runtime policy is loaded from private T3N KV.

`T3N_AGENT_API_KEY` authenticates the Proposal Agent and must not be granted protected remediation functions. `T3N_EXECUTOR_API_KEY` authenticates the separate Protected Executor and must receive only the execution/verification functions and hosts/scopes it needs. The Executor's fixed effective check includes `verified_contacts.email.value` for the protected notification branch; the Proposal Agent remains limited to `evaluate-action`.

`AUDIT_INTEGRITY_KEY` authenticates the local audit chain and must contain at least 32 characters. `AUDIT_INTEGRITY_KEY_ID` selects the active version; `AUDIT_INTEGRITY_PREVIOUS_KEYS` retains explicit `keyId=secret` historical material during planned rotation. Normal runtime keeps `AUDIT_INTEGRITY_ALLOW_LEGACY_BOOTSTRAP=false`, so pre-HMAC rows remain honestly unverified.

`SECURITY_API_URL` is the protected action endpoint. Its full URL remains private; only the hostname persisted in the proposal is human-approved and capability-bound. `SECURITY_VERIFICATION_URL` is the independent read-back endpoint and may use a different host because it verifies the result rather than receiving the authorized side effect. Both URLs are seeded into the T3N private map by the setup script; neither URL becomes a browser/backend credential.

`EVIDENCE_RUN_DESTINATION_BINDING=true` enables the controlled A→B mutation scenario only on T3N testnet. `EVIDENCE_DESTINATION_B_URL` must point to a synthetic second destination. The runner temporarily changes the private action URL, requires the contract to return `EXECUTION_DESTINATION_CHANGED` before `hwp::call`, and restores the original URL in `finally`. This mutation is explicitly forbidden outside testnet.

`EVIDENCE_RUN_PAYLOAD_MINIMIZATION=true` enables the controlled synthetic value-level minimization proof on T3N testnet. It must remain disabled unless the action/read-back endpoints can report only the two documented boolean observations without reflecting raw sentinel values.

`EVIDENCE_RUN_PROFILE_PLACEHOLDER=true` enables the opt-in `LIVE-PROFILE-PLACEHOLDER-RESOLUTION` testnet proof. It requires a compatible synthetic T3N profile/user context, controlled notification/read-back endpoints and `EVIDENCE_NOTIFICATION_AUTHORIZATION_PROOF`, a real v2 one-time proof produced by the authenticated human-authorization flow for the exact synthetic request. The proof is never written to public evidence. Without a real successful run, this scenario remains `NOT_RUN`.

Business APIs require the Spring Security operator session and CSRF protection. The browser never receives T3N keys, AI provider keys, internal service token, remediation capability, remediation credential, audit-integrity key or resolved profile PII.

## T3N operational status

The dashboard reports independent observed states:

```text
Gateway                    ONLINE / UNAVAILABLE
Tenant                     AUTHENTICATED / NOT AUTHENTICATED
Proposal Agent             AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Protected Executor         AUTHENTICATED / NOT AUTHENTICATED / NOT CONFIGURED
Onboarding                 REGISTERED / NOT_REGISTERED / MISMATCH / UNAVAILABLE
Contract                   RESOLVED / UNAVAILABLE
Proposal Member grant      ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
Proposal Effective access  CONFIRMED / DENIED / UNKNOWN
Executor Member grant      ACTIVE / SCHEDULED / REVOKED / NOT_GRANTED / UNKNOWN
Executor Effective access  CONFIRMED / DENIED / UNKNOWN
```

`AUTHENTICATED` means a T3N principal session proved control of its credential and returned its canonical DID. `REGISTERED` means a public T3N Agent Card for the Proposal Agent DID was resolved and passed the closed card validation. Member grant state reflects the tenant delegation document and validity window. Effective access reflects `checkDelegation` performed through the authenticated delegated principal for the exact contract, canonical Tenant DID, functions and scopes.

Evaluation readiness requires Proposal Agent authentication, contract resolution, Proposal Member grant `ACTIVE` and Proposal Effective access `CONFIRMED`. Protected remediation readiness additionally requires Protected Executor authentication, Executor Member grant `ACTIVE` and Executor Effective access `CONFIRMED`. `DENIED` and `UNKNOWN` never produce a positive readiness state.

`RESOLVED` means contract id/version were resolved. It is not hardware attestation. Delegated functions/scopes/hosts and separately checked functions/scopes are exposed as sanitized technical status metadata.

## Policy and remediation exports

The Rust contract exports:

```text
evaluate-action
execute-remediation
verify-remediation
```

`evaluate-action` returns the exact policy version/hash used by the TEE. `execute-remediation` requires the approved version/hash, exact canonical approved hostname and trusted normal payload, resolves the private `security_api_url`, rejects host substitution before HTTP, validates/minimizes normal values against `allowed_fields`, re-evaluates the executable subset and only then performs protected egress. For `notify-security`, only Rust adds the verified-email profile marker after the closed private-reference checks. Execution can return only bounded acceptance metadata needed for reconciliation; `operation_id` is accepted only under the safe opaque identifier grammar. `verify-remediation` has action-specific closed contracts: `revoke-credential -> REVOKED`, `notify-security -> DELIVERED` with `recipient_resolved=true`. Its optional payload-minimization proof exposes only the two bounded booleans used by controlled evidence. A capability is rejected when its signed incident/action/decision/request/action/resource/purpose/approvedHost/fields/normalPayloadHash/privateRefs/policyVersion/policyHash/Executor DID differ from the body/runtime identity, when expired or when its nonce was already consumed.

## Evidence

The project distinguishes local controls from live T3N proof. It does not upgrade mocks, unit tests or unexecuted scenarios into live evidence.

Local controls:

```bash
bash scripts/run-local-evidence.sh
```

Live T3N evidence:

```bash
cd t3n-gateway
npm install
npm run evidence:live
```

Generated artifacts are `docs/evidence/deployment-manifest.json` and `docs/evidence/testnet-run.json`. The orchestrator binds WASM SHA-256, canonical tenant/Proposal/Executor DIDs, contract id/version and policy version/hash. It provisions least-privilege Member grants, performs principal-side `checkDelegation` for Proposal and Executor, aborts unless both are effectively `ACTIVE`, and fails on mismatch, scenario `FAIL` or configured secret leakage. The deployment manifest also records the observed Agent Card registration state and, when a card is resolved, its public URI, SHA-256, verification time and service names. `NOT_RUN` is never counted as `PASS`.

`testnet-run.json` records a sanitized `delegation` object for Proposal Agent and Protected Executor containing only `memberState`, `effectiveState`, `checkedFunctions` and `checkedScopes`. It never persists the full Member Delegation document, SDK `satisfied`/`missing` payloads, private keys, API keys, tokens or trusted normal-payload values.

Agent Card metadata proves only what was observed during public resolution. `REGISTERED` means the resolved card matched the authenticated Proposal Agent DID and supported service schema; it does not prove Member grant, effective T3N access, policy authorization, TEE execution or hardware attestation.

For live remediation proof, both `SECURITY_API_URL` and `SECURITY_VERIFICATION_URL` must be configured/sealed and the Executor delegation includes only their derived HTTPS hosts. A live remediation scenario passes only on the documented execution plus independent verification sequence. An accepted 2xx without read-back cannot become a passing completion claim.

The optional `LIVE-DESTINATION-BINDING` testnet scenario approves host A, independently confirms policy ALLOW for host B, mutates only the private `security_api_url` to B, and requires `BLOCKED_BEFORE_HTTP` through `EXECUTION_DESTINATION_CHANGED`. The original URL is restored in `finally`; outside testnet the scenario is rejected instead of run.

The optional `LIVE-NORMAL-PAYLOAD-MINIMIZATION` testnet scenario requires controlled external proof that a synthetic allowed value arrived while a synthetic redacted value did not. Only `must_egress_seen` and `must_not_egress_seen` may be persisted as public proof. A `NOT_RUN` result remains explicitly non-evidence.

`LIVE-PROFILE-PLACEHOLDER-RESOLUTION` is also opt-in and remains `NOT_RUN` until actually executed on T3N testnet with a compatible synthetic verified-email profile/user context and a v2 human-authorization proof bound to the exact notification request. The dedicated runner sends only the logical `verified_email` reference through application layers, executes `notify-security`, and accepts PASS only after independent read-back returns `VERIFIED`, `DELIVERED` and `recipient_resolved=true`. It persists only decision/execution/verification states and the boolean resolution assertion, explicitly rejects raw `{{profile.*}}` markers from the bundle and leak-scans configured secrets plus the authorization proof. Local Rust/Java/gateway/frontend tests remain local architectural proof and do not upgrade this live scenario.

The submission capture harness rejects AI/T3N/operator/service/capability/audit-integrity secrets in generated metadata and captures a remediation success only after the UI shows independently verified `COMPLETED`. Local audit integrity is rendered as a separate application signal from T3N Activity Log reconciliation and is not upgraded into live T3N proof.

## Terminal 3 integration findings

The submission guide records the concrete `scopes` documentation inconsistency, the delegated `pii_did` authorization-subject requirement, the difference between Member Delegation read-back and effective `checkDelegation`, exact approved-destination binding and value-level normal-payload minimization. This project always sends explicit minimum scopes, derives `pii_did` from the authenticated tenant session and requires the delegated principal itself to perform the effective check.

Terminal 3 contract-host compatibility is treated as a breaking runtime contract. After the function-scoped grant ABI change, each Tenant grant represents one contract function; `delegated-scopes()` exposes structured `{ path, access }` records; `delegated-read-scopes()` is removed; and the literal `"*"` is the all-functions marker. Privacy Guard must not provision that wildcard in its normal least-privilege flow.

Any incompatible Terminal 3 host upgrade requires a WASM rebuild, a **major** `CONTRACT_VERSION` bump, synchronized Cargo/WIT/gateway version metadata, upload of the rebuilt WASM to the existing Tenant contract slot, a compatible SDK/CLI, and re-validation of previously provisioned grants. Rebuilding remains mandatory even when the contract does not directly call the changed accessors, because a WASM artifact linked to a removed host can fail to instantiate with `500 internal_error`. Until the contract artifact, gateway and grants are reconciled to the current ABI, the deployment must not be represented as ready or as positive live evidence.

## Pinned toolchain

- Node: `22.20.0-alpine3.22`
- React / React DOM: `19.3.0`
- Vite: `8.2.2`
- `@vitejs/plugin-react`: `6.1.1`
- TypeScript: `5.9.2`
- T3N SDK: **`5.12.0`**
- Express: `5.1.0`
- Maven image: `3.9.16-eclipse-temurin-21`
- Java runtime: `eclipse-temurin:21.0.12_8-jre`
- Nginx: `1.27.5-alpine3.21-slim`
- Rust contract: `0.4.5`, target `wasm32-wasip2`; the Alpine Docker contract builder installs `build-base` and `musl-dev` so host procedural macros can link before the WASI artifact is produced

## Local builds

```bash
cd backend && mvn test && mvn package
cd ../frontend && npm install && npm test && npm run typecheck && npm run build
cd ../t3n-gateway && npm install && npm test && npm run typecheck && npm run build
cd ../contracts/privacy-guard && cargo test && cargo build --target wasm32-wasip2 --release
```

## Environment

Use `.env.example` only as a variable-name template. Never commit tenant keys, Proposal Agent keys, Protected Executor keys, AI provider keys, operator passwords, service tokens, capability keys, audit-integrity keys, remediation credentials, private profile values or `.env` files.

The project will continue to be operated after the challenge. Future handover provisions new credentials instead of transferring existing private keys.

## Persistent T3N trust-manifest rollback protection

Before tenant, Proposal Agent or Protected Executor authentication, the gateway verifies the official signed T3N trust manifest and persists the accepted manifest version as a monotonic high-water mark per network. `T3N_TRUST_FLOOR_STORE_PATH` defaults to `/data/t3n-trust-floor.json`; the file contains only public trust metadata (`network`, accepted version and timestamp), never API keys, cookies or session credentials.

When a floor already exists, authentication calls `fetchTrustedManifest(network, { minVersion })`. A lower manifest is rejected, the floor is never silently decreased, and malformed or unreadable persisted state fails closed instead of resetting rollback history. Tenant, Proposal Agent and Protected Executor sessions receive the same `TrustManifestFloorStore` instance in each runtime, so they cannot establish independent floors for the same network. Atomic temp-file + fsync + rename persistence allows the accepted floor to survive process/container restart when `/data` is persistent.

Evidence uses precise wording: `Trust anchor VERIFIED` means the signed manifest established the T3N cluster trust boundary used for authentication; `Rollback floor PERSISTED` means the version high-water mark was durably stored and reused across restarts. Neither claim is described as per-request hardware attestation.

## Authenticated human authorization provenance

The `Humans authorize` boundary is durable provenance, not a boolean supplied by the browser. `POST /authorize-remediation` derives the approver exclusively from the authenticated Spring `SecurityContext`; the client cannot submit `authorizedBy`. The action persists the canonical application principal and the first valid authorization timestamp. A retry by the same principal is idempotent and preserves the original timestamp; a different principal cannot silently overwrite the existing approval.

The local tamper-evident audit records the sanitized approving principal in the `REMEDIATION_AUTHORIZED` event, so the existing HMAC chain authenticates that provenance together with the rest of the event. This application principal is not presented as a civil identity or a T3N DID and is not published in Agent Card, public evidence or T3N Activity Log.

Before protected execution, Spring refuses to issue a capability unless the persisted human provenance is present. The capability carries only `operatorPrincipalHash = SHA-256(UTF8(canonicalPrincipal))` plus the persisted `authorizedAt`, alongside the exact action, decision, policy version/hash, approved destination, trusted payload hash and Protected Executor DID. The gateway requires an exact hash/timestamp match and rejects missing, malformed, future or body-mismatched provenance before T3N execution.

Legacy actions whose status says `REMEDIATION_AUTHORIZED` but predate `remediationAuthorizedBy/remediationAuthorizedAt` are never upgraded by inference. They are shown as `REAUTHORIZATION REQUIRED` and protected execution remains blocked until an authenticated operator explicitly authorizes again. Completed legacy remediations are not rebound retroactively to a new operator.

## Human separation of duties

Application identity is now split from the T3N identity model and, when enterprise SoD mode is enabled, from one universal human operator. Spring Security is the source of truth for four semantic application authorities:

```text
ANALYST   -> create incidents, run agent analysis, create/evaluate proposals
APPROVER  -> authorize protected remediation
EXECUTOR  -> start and verify protected remediation
AUDITOR   -> read operational, audit and evidence state; no business mutation
```

Set `ENTERPRISE_SOD_ENABLED=true` only when `ANALYST_USERNAME/PASSWORD`, `APPROVER_USERNAME/PASSWORD`, `EXECUTOR_USERNAME/PASSWORD` and `AUDITOR_USERNAME/PASSWORD` are all configured with four distinct usernames. Missing credentials, documentation placeholders or duplicate principals fail application startup. This configuration is a local application-IAM boundary for the current deployment architecture; it is deliberately **not** described as an external corporate IdP/OIDC integration.

When `ENTERPRISE_SOD_ENABLED=false`, the configured `OPERATOR_USERNAME/PASSWORD` receives all four semantic authorities so the existing local/demo flow remains usable. That compatibility mode is explicitly labelled `LOCAL / DEMO MODE` and is not evidence of enterprise segregation of duties.

The API enforces the authority matrix before controller business logic. The frontend only uses the session's returned authorities to hide or explain unavailable actions; a manually crafted request with the wrong authority still receives `403` from Spring Security. The session contract never accepts a role or username from the request body as authorization evidence.

Enterprise remediation also applies a per-action principal rule:

```text
principal that authorized remediation != principal that executes or verifies remediation
```

This comparison is by canonical authenticated principal, so assigning multiple roles to the same account does not bypass SoD. The execution claim persists `executionPrincipal` from the authenticated server-side `SecurityContext`; legacy execution rows without that field remain unproven rather than being retroactively classified as compliant. The remediation UI shows `Authorized by`, `Execution principal` and `Separation of duties` separately, and the local audit records the execution-start principal without treating it as a T3N DID or verified civil identity.

Relevant application-IAM variables are:

```text
ENTERPRISE_SOD_ENABLED
ANALYST_USERNAME
ANALYST_PASSWORD
APPROVER_USERNAME
APPROVER_PASSWORD
EXECUTOR_USERNAME
EXECUTOR_PASSWORD
AUDITOR_USERNAME
AUDITOR_PASSWORD
OPERATOR_USERNAME
OPERATOR_PASSWORD
```

These human application credentials never replace `T3N_AGENT_API_KEY`, `T3N_EXECUTOR_API_KEY`, Member Delegation, `checkDelegation`, the one-time capability or the Protected Executor DID. They add a separate human governance boundary around the existing T3N trust path.

## Measured control impact

`GET /api/business-impact?window=retained|24h|7d` exposes a read-only, authenticated aggregate of operational outcomes that are already persisted by the application. `BusinessImpactService` is the single calculation source; React renders the returned values and does not independently recompute rates or medians. The full summary belongs to Protection flow, while Executive Demo projects only blocked, minimized, verified and median decision values.

The observation window is always bounded by configured incident retention. If a requested 7-day window exceeds retained history, `from` is moved to the retention floor and `retentionLimited=true`. Purged data is not reconstructed or described as historical coverage. The response contains counts, timestamps and rates only; it does not return prompt text, usernames, trusted normal payload values or private profile values.

The aggregate uses these exact semantics:

```text
blockedRatePct = DENY / evaluatedDecisions * 100

finalizedExecutions = COMPLETED + UNVERIFIED + FAILED
verifiedCompletionRatePct = COMPLETED / finalizedExecutions * 100

per-decision latency = decision.evaluatedAt - action.createdAt
medianDecisionMs = median(valid non-negative per-decision latencies)

per-verified-outcome latency = remediation.completedAt - action.createdAt
medianVerifiedOutcomeMs = median(valid non-negative COMPLETED latencies)

redactedNormalFieldNames = sum(size(decision.redactedFields))
redactedPrivateRefs = sum(size(decision.redactedPrivateRefs))
```

`EXECUTING` and `PENDING_VERIFICATION` never enter the finalized-execution denominator. When a denominator or valid latency sample does not exist, the API returns `null` and the UI says `NOT OBSERVED`; it does not display `0%` as evidence. For an even number of latency samples, the median is the arithmetic mean of the two center values rounded to the nearest integer millisecond.

`DENY` is counted as blocked before protected egress because policy evaluation precedes human authorization and protected execution in this runtime. `REDACT` counts a minimization decision; it does not mean an incident was prevented. `COMPLETED` counts only the already-existing independently verified terminal state. Redacted field/ref totals count schema names/categories, not bytes, people or leaked values.

The product deliberately does **not** convert these operational measurements into money saved, breach cost avoided, risk-reduction percentage, SLA compliance, regulatory compliance or ROI. Those inputs are not measured by this runtime, so **financial ROI remains NOT MEASURED**.