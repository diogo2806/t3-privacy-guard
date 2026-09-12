# T3 Privacy Guard — Submission & Judge Guide

## Executive summary

T3 Privacy Guard is a confidential incident-response agent built around a hostile assumption: the AI agent itself may be manipulated by prompt injection or malicious external data. Instead of trusting the LLM to obey policy, critical authorization is enforced outside the model through Terminal 3 identities, member delegation and a Rust/WASM policy contract executed through T3N.

The signature flow is intentionally adversarial. An injected instruction asks the agent to exfiltrate a protected credential to an undelegated host. The policy returns `DENY`. The same incident can still produce a minimum legitimate credential-revocation request. After `ALLOW` and explicit authenticated human authorization, protected remediation executes while the remediation credential remains in the tenant private map and outside the browser, Spring Boot API and AI-agent context.

The project prioritizes verifiable state over presentation claims: authenticated identities, resolved contract version, observed delegation and evidence are displayed separately; `NOT_RUN` never becomes `PASS`; no hardware-attestation claim is made unless a concrete T3N artifact supports it.

## Judge quick path

Recommended evaluation order:

```text
1. Sign in as the application operator
2. Confirm Gateway / Tenant / Agent / Contract / Delegation separately
3. Run attack scenario
4. Observe DENY for credential exfiltration
5. Prepare minimum safe remediation
6. Observe ALLOW
7. Record explicit human authorization
8. Execute protected remediation when the synthetic egress environment is enabled
9. Open Evidence
10. Confirm source=T3N_TESTNET, contract/version, DIDs, WASM SHA-256 and scenario results
```

The visual demo should take only a few minutes. For technical reproduction, use the commands under **Reproduction** below.

## Architecture and trust boundaries

```text
Browser / Nginx             Spring Boot              T3N Gateway             T3N / TEE
      |                           |                         |                       |
  untrusted UI              business state           T3N private keys       policy + private KV
      |                           |                         |                       |
      +------ HTTPS / API ------>+---- internal net ----->+------ T3N ----------->+
      |                           |                         |                       |
 operator session            replay/idempotency       tenant + agent sessions   delegation / egress
```

Trust model:

- **Browser is not a trusted security boundary.** Buttons can be bypassed, so the backend enforces operator authentication, CSRF and business authorization.
- **LLM/agent may be compromised.** Its proposed action is treated as untrusted input.
- **Spring Boot owns durable business state.** It persists incidents, decisions, audit metadata and replay/idempotency state. It does not receive T3N private keys or the remediation credential.
- **T3N Gateway owns T3N sessions.** Tenant and agent authenticate separately. Canonical DIDs come from authenticated sessions.
- **Rust/WASM contract owns the critical policy decision.** Action, purpose, host and requested data are evaluated independently of the LLM.
- **Private KV owns remediation secrets.** The protected credential is consumed inside the T3N contract path and is not returned to browser, Java or agent context.
- **Member delegation limits authority.** Contract, functions, scopes, hosts and validity determine what the agent may do on behalf of the tenant.
- **Human operator authorization is separate from T3N authorization.** A policy `ALLOW` does not execute an action; the authenticated operator must authorize remediation before the backend can request protected execution.

Out of scope:

- claiming formal GDPR certification/compliance;
- claiming generic immunity to all model compromise;
- claiming hardware attestation when no attestation artifact is present in the evidence bundle;
- protecting a host operating system or deployment account after full infrastructure compromise;
- replacing the upstream enterprise security product being called by the remediation adapter.

## Security claims matrix

This table is intentionally conservative before the final live evidence run.

| Claim | Current status | Source of truth |
|---|---|---|
| Tenant DID is derived from authenticated T3N session | PROVED LOCAL | gateway session code/tests; live confirmation will be in evidence |
| Agent uses a separate credential/DID | PROVED LOCAL | config/session separation tests; live DID separation will be in evidence |
| Delegated calls bind `pii_did` to canonical tenant DID | PROVED LOCAL | `privacy-guard-contract.test.ts` |
| Direct secret disclosure request is denied by policy | PROVED LOCAL | Rust adversarial tests |
| Undelegated host is denied by policy | PROVED LOCAL | Rust adversarial tests |
| Excess non-secret fields produce `REDACT` | PROVED LOCAL | Rust adversarial tests |
| Duplicate request/replay is rejected or reused idempotently | PROVED LOCAL | Spring service tests |
| A persisted `DENY` cannot be human-authorized | PROVED LOCAL | Spring service tests |
| Remediation requires authenticated operator + CSRF + explicit authorization | PROVED LOCAL | Spring Security/integration tests |
| Reflected upstream secret/header is not returned by remediation result | PROVED LOCAL | Rust remediation regression test |
| Evidence artifacts reject configured secret/sentinel values | PROVED LOCAL | leak-detector tests |
| Revoked/limited delegation blocks protected egress on T3N testnet | NOT CLAIMED | becomes live claim only after successful `evidence:live` optional negative scenarios |
| Attack `DENY` followed by protected remediation `COMPLETED` on T3N testnet | NOT CLAIMED | becomes live claim only after successful protected-evidence run |
| Hardware attestation for this specific execution | NOT CLAIMED | no claim without explicit T3N attestation artifact/API evidence |

After a successful `npm run evidence:live`, only claims directly represented by the matching `deployment-manifest.json` + `testnet-run.json` should be described as **PROVED LIVE** in the public submission document.

## Signature security flow

```text
Untrusted security log / prompt injection
               |
               v
        AI proposes action
               |
               v
     Rust/WASM policy in T3N
      |         |          |
     DENY     REDACT     ALLOW
      |         |          |
      |         |          +----> still NOT executed
      |         |                        |
      |         |                authenticated operator
      |         |                        |
      |         |                explicit authorization
      |         |                        |
      |         |                        v
      |         +----------------> protected remediation
      |                                  |
      |                                  v
      +-------------------------- private KV + delegated egress
```

## Terminal 3 integration findings

### Finding 1 — Member Delegation example omits `scopes`

**Observed source:** current Terminal 3 member-delegation documentation used during the challenge.

**Expected:** an example of `member-delegation-update` / `updateMemberDelegation` should include all fields required by the same page's field reference.

**Observed:** the example omits `scopes`, while the reference describes `scopes` as required.

**Impact:** a developer copying the example literally can create an incomplete/rejected grant or misunderstand the required authorization model.

**Project workaround:** `DelegationService.grant` validates that `functions` and `scopes` are non-empty and always sends explicit scopes.

**Classification:** documentation inconsistency, not a platform-security bypass.

### Finding 2 — delegated-call `pii_did` subject is easy to misconfigure

**Expected:** an agent acting for a tenant must cause authorization to be checked under the tenant/data-owner grant.

**Observed:** authenticated agent identity identifies the caller, while `pii_did` selects the grant/data subject. Omitting it can lead to authorization being evaluated under the agent's own DID and surface as an authorization/egress failure.

**Impact:** valid delegation can appear broken, and a developer can debug the wrong layer.

**Project workaround:** every delegated `executeAndDecode` request derives `pii_did` internally from `tenantSession.getTenantDid()`. Browser and Java payloads cannot supply or override it.

**Classification:** integration gotcha with security relevance, not a bypass.

## Post-challenge operation decision

**Decision: continue running the project after the challenge.**

The implementation is structured so operation can later be handed to Terminal 3 or another maintainer without transferring existing private keys.

## Handover runbook

A handover must provision new secrets rather than copying the current operator's private material.

1. Provision a new tenant credential and a separate agent credential.
2. Rotate/revoke prior credentials according to the account/network controls available at handover time.
3. Configure runtime variable names documented in `.env.example`; never commit values.
4. Build the Rust contract for `wasm32-wasip2`.
5. Register the intended contract version with the new tenant or resolve the existing intended version.
6. Record the numeric contract id where private-map administration requires it.
7. Seed a new private remediation map using a new upstream credential.
8. Create the minimum member delegation for the agent: exact contract/version, functions, scopes, hosts and validity.
9. Configure a new application operator username/password and invalidate the old operator session/credential.
10. Run `npm run evidence:live` with synthetic remediation credentials first.
11. Verify Evidence Center shows matching DIDs, contract/version/hash and no `FAIL` scenarios.
12. Only then configure any production upstream security endpoint.

No handover step requires publishing or sending an existing T3N private key through GitHub, the UI or the submission document.

## Evidence model

Live proof is a linked pair:

```text
WASM bytes
   | SHA-256
   v
docs/evidence/deployment-manifest.json
   | same network / DIDs / contract / version / hash
   v
docs/evidence/testnet-run.json
```

The Evidence Center reads an allowlisted projection of those files through the authenticated Spring API. It does not execute T3N and never reads raw runtime logs or `.env`.

States:

- `PASS`: observed result matched expected security outcome.
- `FAIL`: observed result did not match expected outcome.
- `NOT_RUN`: scenario was not executed in this bundle; never counted as PASS.

## Reproduction

### Local controls

```bash
bash scripts/run-local-evidence.sh
```

### Build the TEE contract

```bash
rustup target add wasm32-wasip2
cd contracts/privacy-guard
cargo test
cargo build --target wasm32-wasip2 --release
```

### Live testnet evidence

```bash
cd t3n-gateway
npm install
npm run evidence:live
```

Full synthetic protected-egress proof, after the numeric contract id/private-map prerequisites are available:

```bash
EVIDENCE_PREPARE_EGRESS=true \
EVIDENCE_RUN_EGRESS_NEGATIVES=true \
EVIDENCE_RUN_REMEDIATION=true \
EVIDENCE_SENTINEL_SECRET='a-synthetic-sentinel-value' \
npm run evidence:live
```

The command must fail on scenario `FAIL`, identity/version/hash mismatch or detected secret material.

## Screenshot shot list

Capture only real application states, in this order:

1. **Operational status:** tenant/agent authenticated, contract resolved, delegation ACTIVE.
2. **Attack proposal:** destination `attacker.example` and secret-bearing field request visible as metadata only.
3. **DENY:** policy reason visible.
4. **REDACT:** Evidence Center scenario showing data minimization when live evidence includes it.
5. **Safe remediation ALLOW:** minimum request, before execution.
6. **Human authorization:** state showing that ALLOW and execution are separate steps.
7. **Protected remediation completed:** only when synthetic egress is enabled and actually succeeds.
8. **Evidence Center:** source T3N_TESTNET, contract/version/hash, DIDs, PASS/FAIL/NOT RUN totals.
9. **Delegation negative evidence:** revoked/function-restricted result when that live scenario was executed.

Do not capture operator passwords, cookies, T3N private keys, remediation keys, `.env`, raw logs or a simulated/local screen labelled as live.

## Demo video storyboard

Target narrative: approximately 90–180 seconds.

```text
0–15s    Problem: an AI incident agent can be prompt-injected
15–35s   Show separate live tenant/agent/contract/delegation status
35–55s   Run malicious exfiltration proposal -> DENY
55–75s   Explain REDACT/data minimization evidence
75–100s  Prepare legitimate minimum remediation -> ALLOW
100–125s Show explicit human authorization as a separate gate
125–150s Execute synthetic protected remediation when enabled
150–180s Open Evidence Center and finish on T3N_TESTNET proof metadata/results
```

The recording must not use overlays or edits that change the application's actual security state.

## UX/claim wording rules

Use these terms precisely:

- **authenticated**: session identity was authenticated;
- **resolved**: contract id/version could be resolved;
- **delegated**: member grant was observed and active;
- **executed**: the operation actually ran;
- **proved live**: matching live evidence artifact exists;
- **secretless from application/agent layers**: secret is not exposed to browser, Java or AI agent; do not say the system contains no secret;
- do not say “guarantees GDPR compliance”;
- do not say “hardware verified” without explicit attestation evidence.

## Submission assembly

The external challenge submission should point to:

- public GitHub repository;
- public submission document derived from this guide;
- screenshots generated from real states listed above;
- short demo video;
- Terminal 3 findings reproduced above;
- live evidence artifacts once generated.

This file is the repository source of truth for the public submission narrative. Do not maintain a second divergent threat model or handover guide.
