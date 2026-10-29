# Privacy Guard

A control layer between AI agents and the systems they act on. The agent may propose an action; a separate trust runtime decides whether it is allowed, strips it to the minimum data, waits for an authenticated human, performs it with credentials the agent never sees, and only calls it done after reading the result back from the target system.

It is demonstrated on security incident response (revoke a leaked credential, notify the security contact), but the pattern applies wherever an agent can trigger something with sensitive data or privileged access: identity and HR workflows, finance and compliance operations, support agents, autonomous enterprise agents.

## Why

Agents get enough context and credentials to be useful. That couples two things that should be separate: whoever proposes an action is also trusted to authorize it. A prompt injection, a compromised model or a bad instruction then becomes data access or a real side effect.

Privacy Guard breaks that coupling:

- The model gets a narrow proposal surface: action, resource, purpose, destination host, field names, logical private references. It cannot set a decision, an identity, a capability, payload values or a secret.
- Policy is evaluated by a different process with its own credentials.
- Private values travel as references (`verified_email`) and are resolved only in the outbound call.
- An HTTP 2xx is not completion. `COMPLETED` requires an independent read-back of the expected state.

## Architecture

Two services:

```text
             browser (dashboard)           external agents (MCP)
                     \                            /
                      v                          v
   +--------------------------------------------------------------+
   | app  (Spring Boot, one image)                                |
   |  dashboard · operator sessions · incidents · AI proposals    |
   |  human authorization (signs one-time capability) · audit     |
   |  MCP endpoint /mcp                                           |
   +--------------------------------------------------------------+
        | proposal token: evaluate only                | executor token: execute + verify only
        v                                              v
   +--------------------------------------------------------------+
   | guard-runtime  (Spring Boot, separate process)               |
   |  policy · capability verification · replay protection        |
   |  minimized protected egress · independent read-back          |
   |  private config: security API URL/key, verified email        |
   |  hash-chained activity log                                   |
   +--------------------------------------------------------------+
                                   |
                                   v
                       security API (your tooling)
```

- [`guard-runtime/`](guard-runtime/README.md): the trust runtime. Holds the policy, the private values and the security API credentials. It is the only component that can cause a side effect.
- `backend/` + `frontend/`: the app. The backend serves the dashboard build, the REST API and the MCP endpoint, and calls the AI provider. The root `Dockerfile` builds both into one image.

The app never holds the security API key or the verified email; guard-runtime never holds the capability signing key or talks to the AI model.

## Two scenarios

**Compromised agent.** A prompt injection makes the model propose sending `api_key` to `attacker.example`. guard-runtime returns `DENY` with a reason code. Nothing leaves; there is no override the model can send.

**Legitimate remediation.**

```text
AI proposes the minimum action + destination A
  -> guard-runtime policy: ALLOW, or REDACT that drops unnecessary fields
  -> authenticated human authorizes the exact action and destination A
  -> app signs a short-lived one-time capability bound to: action, decision, destination A,
     field set, trusted payload hash, private references, policy version/hash, executor id
  -> guard-runtime: verifies the capability, burns its nonce, checks the configured
     destination still equals A, re-checks the current policy, sends only surviving fields
  -> PENDING_VERIFICATION
  -> independent read-back
       expected state observed  -> COMPLETED
       ambiguous / mismatch     -> UNVERIFIED (never re-executed automatically)
```

For `revoke-credential` the expected state is `REVOKED`; for `notify-security` it is `DELIVERED` with `recipient_resolved=true`.

## The AI agent

"Ask agent" sends the operator's prompt to any OpenAI-compatible chat-completions endpoint: OpenAI, Azure OpenAI, a gateway in front of Claude or Gemini, or a local model behind Ollama or vLLM. The call forces one structured tool call, `propose_privacy_guard_action`; the result is validated strictly (allowed keys only; `decision`, `allow`, `credential`, identities and similar keys are rejected) before anything is stored. A prompt that contains a literal credential, token or personal data is rejected before it reaches the provider.

The AI is optional. Scenarios and manual proposals work with `AI_PROVIDER=disabled`.

### MCP

Agents you already run (Claude, Copilot, internal agents) can use Privacy Guard as their safety check through MCP at `POST /mcp` (Streamable HTTP, JSON responses, `Authorization: Bearer <MCP_TOKEN>`):

| Tool | What it does |
|---|---|
| `privacy.contract_identity` | Trust runtime id and version |
| `privacy.evaluate_action` | Policy decision for a proposed action, with redactions and reason code |
| `privacy.verify_remediation` | Independent read-back of a remediation |

MCP exposes evaluation and read-back only. Human authorization and protected execution stay in the dashboard flow.

## Private data

The application carries the logical reference `verified_email`, never the address:

| Component | Sees the plaintext |
|---|---|
| AI model | no |
| Browser | no |
| app (API, database, audit) | no |
| guard-runtime | only while building the outbound request |
| Security API | yes, as the intended recipient |

Upstream responses are reduced to bounded metadata; an `operation_id` must be an opaque ASCII identifier, so a reflected address cannot come back disguised as metadata. This does not cover free text an operator types: the prompt guard is a best-effort filter for obvious literals.

## Policy

The policy is a JSON document enforced by guard-runtime (example: [`deploy/local/policy.json`](deploy/local/policy.json)). Each action declares its purpose, allowed fields, allowed hosts, allowed private references, whether a host is required and whether human authorization is required. Every decision carries `policyVersion` and `policyHash`, and the capability binds them, so an approval cannot be reused after the policy changes: guard-runtime refuses it before any external call and the remediation ends as `FAILED` with `POLICY_CHANGED_AFTER_AUTHORIZATION`.

### Policy editor

With `GUARD_RUNTIME_POLICY_DIR` set, guard-runtime keeps the policy as immutable versions plus a hash-chained history (checked at startup), and the dashboard's **Policy** tab becomes an editor:

- edit the rules per action, see the changes against the active version, ask guard-runtime to validate the draft, then publish it under a new version name;
- publishing sends the hash of the version being edited, so two administrators cannot overwrite each other's change;
- any earlier version can be made active again with a rollback;
- the history records each change, the human who requested it (as reported by the app) and the guard-runtime caller that made it.

The app reaches these functions with a third guard-runtime caller granted only `manage-policy` (`GUARD_RUNTIME_POLICY_ADMIN_TOKEN`). Without a policy directory, the file is the policy and the tab is read-only; with one, the file only seeds a version that was never published, so keeping policy in Git and restarting still works.

Some rules cannot be relaxed by the document: secret fields (`api_key`, passwords, tokens, private keys) are always denied, unknown actions, purposes, hosts and references fail closed, and sizes are bounded.

Current vocabulary:

| Action | Purpose | Minimum fields | Private reference | Protected execution |
|---|---|---|---|---|
| `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none | yes |
| `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | exactly `verified_email` | yes |
| `isolate-account` | `incident-remediation` | `incident_id`, `account_id`, `reason` | none | evaluation only |
| `create-incident` | `incident-recording` | `incident_id`, `severity`, `summary`, `source` | none | evaluation only |

## Human governance

Five application roles: `ANALYST` (incidents, agent analysis, proposals), `APPROVER` (authorizes remediation), `EXECUTOR` (executes and verifies), `AUDITOR` (read-only, including the policy) and `POLICY_ADMIN` (publishes and rolls back policy versions). With `ENTERPRISE_SOD_ENABLED=true` each role is a distinct account (the policy administrator is optional) and the account that authorized a remediation can never execute or verify it. Without it, a single operator account holds all roles; the dashboard labels that mode as local/demo.

## Audit

- **App:** every audit event is chained per incident with HMAC-SHA-256 (`AUDIT_INTEGRITY_KEY`), with an authenticated chain head, so edits, insertions, reordering and tail deletion in the database are detected. This is tamper-evident, not tamper-proof: someone holding both the database and the key can forge it.
- **guard-runtime:** an append-only, hash-chained activity log of every function call; a broken chain stops startup.
- The incident's audit view reconciles both: each local event that claims a runtime call must match that call's sequence, function, hash and caller.

`GET /api/business-impact?window=retained|24h|7d` reports measured outcomes only: blocked rate, verified completion rate, median decision and verified-outcome latency, redacted field counts. Missing data is shown as not observed, never as zero, and nothing is converted into money.

## Running

With Docker (two containers):

```bash
cd deploy/local
./init-env.sh
docker compose up --build
```

Then open http://localhost:8088. See [`deploy/local/README.md`](deploy/local/README.md).

Without Docker, the end-to-end check builds everything, starts both services and drives both remediations to `COMPLETED`:

```bash
scripts/selfhosted-e2e.sh
```

For dashboard development, run the backend on port 8080 and the Vite dev server, which forwards `/api` to it (`VITE_BACKEND_URL` overrides the target):

```bash
npm --prefix frontend run dev
```

All settings, with comments, are in [`.env.example`](.env.example).

## API

| Path | Who | Purpose |
|---|---|---|
| `/api/auth/*` | browser | Login, session, CSRF, logout |
| `/api/incidents/**` | operator roles | Incidents, proposals, evaluation, authorization, execution, verification, trace, audit evidence |
| `/api/agent/analyze` | `ANALYST` | Ask the AI agent for a proposal |
| `/api/system/status` | operators | Runtime reachability, caller grants, policy and integration readiness |
| `/api/business-impact`, `/api/incident-workspace` | operators | Measured outcomes and the incident queue |
| `/api/policy/**` | `POLICY_ADMIN` (`AUDITOR` reads) | Active policy, history, validate, publish, roll back |
| `/api/integrations/incidents` | intake token | Machine-to-machine incident intake (off by default) |
| `/api/security/remediation/{execute,verify}` | `SECURITY_API_KEY` | Built-in security adapter used by the local stack |
| `/mcp` | `MCP_TOKEN` | MCP endpoint for external agents |

## Repository

| Path | Contents |
|---|---|
| `guard-runtime/` | Trust runtime (Java 21, Spring Boot) |
| `backend/` | App API, MCP, AI client (Java 21, Spring Boot) |
| `frontend/` | Dashboard (React, TypeScript, Vite) |
| `privacy-conformance/` | Corpus of sensitive literals (and near misses) the data minimizer is tested against |
| `deploy/local/` | Compose stack, local policy and secret generator |
| `scripts/selfhosted-e2e.sh` | End-to-end check without Docker |
| `Dockerfile` | App image: dashboard build + backend jar |

## Build and test

Requirements: Java 21, Maven, Node 22+.

```bash
mvn -f guard-runtime/pom.xml test
mvn -f backend/pom.xml test
npm --prefix frontend install
npm --prefix frontend test
npm --prefix frontend run typecheck
```

## Limits

- One guard-runtime instance per tenant; its replay store, activity log and policy versions are local files. Horizontal scaling needs a shared transactional store.
- Callers authenticate with static bearer tokens; mTLS or workload identity is the next step.
- One private value (`verified_email`) and one security API per runtime; real deployments need connectors for their own tooling (IdP, ticketing, messaging).
- Without confidential computing, trust rests on process, credential and operator separation.
- An idempotency key is sent with every protected call, but exactly-once delivery depends on the target system honouring it.

## History

The project started as a competition entry running its policy as a Rust/WASM contract on Terminal 3. That version is kept under the git tags `competition-final` and `dual-runtime`; the current code has no dependency on it.
