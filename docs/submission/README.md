# T3 Privacy Guard — Submission & Judge Guide

## Executive summary

T3 Privacy Guard assumes the agent can be manipulated by prompt injection or malicious external data. Critical authorization is enforced outside the model through Terminal 3 identities, member delegation and a Rust/WASM policy contract executed through T3N.

An unsafe proposal attempts credential exfiltration and receives `DENY`. A minimum legitimate remediation can receive `ALLOW`, but `ALLOW` still does not execute anything. An authenticated operator must authorize the action, then the Spring backend creates a short-lived, one-time signed capability bound to that exact incident/action/decision/request. The gateway verifies service authentication, capability integrity, expiry, payload equality and anti-replay state before invoking protected T3N execution. The remediation credential remains in T3N private KV and outside browser, Java and agent context.

The project reports only verifiable state: authenticated identities, resolved contract version, observed delegation and evidence are separate; `NOT_RUN` never becomes `PASS`; hardware attestation is not claimed without an explicit artifact.

## Judge quick path

```text
1. Sign in as application operator
2. Confirm Gateway / Tenant / Agent / Contract / Delegation separately
3. Run attack scenario -> DENY
4. Prepare minimum safe remediation -> ALLOW
5. Record explicit human authorization
6. Observe one-time execution authorization state
7. Execute protected remediation when synthetic egress is enabled
8. Open Evidence
9. Confirm T3N_TESTNET source, contract/version, DIDs, WASM SHA-256 and results
```

## Architecture and trust boundaries

```text
Browser / Nginx          Spring Boot               T3N Gateway                 T3N / TEE
      |                       |                         |                           |
 untrusted UI           business state        tenant/agent sessions           policy + private KV
      |                       |                         |                           |
      +--- session/API -----> |                         |                           |
                              +-- service token ------->|                           |
                              +-- signed one-time ----->|                           |
                                  capability            +--------- T3N ----------->|
```

Trust model:

- **Browser is untrusted.** Backend enforces operator authentication, CSRF and business state.
- **Agent may be compromised.** Its proposal is untrusted input; it cannot manufacture a policy decision.
- **Spring Boot owns business authorization.** It stores incident/action/decision state and issues a remediation capability only after a persisted `ALLOW` and explicit human authorization.
- **The capability is not an API token.** It is HMAC-signed, short-lived, one-use and bound to `incidentId`, `actionId`, `decisionId`, `requestId`, action, resource, purpose and a canonical fields hash.
- **T3N Gateway owns T3N sessions.** It requires a separate service token for privileged internal routes, validates the capability before remediation and persists consumed nonces so replay remains rejected after process restart when `/data` is persistent.
- **Rust/WASM owns critical policy.** Action, purpose, host and requested data are evaluated independently of the model and Java.
- **Private KV owns remediation secrets.** Secret material is consumed only in the protected contract path.
- **Member delegation limits authority.** Contract, functions, scopes, hosts and validity remain independent requirements.

Out of scope: formal GDPR certification, immunity to full infrastructure compromise, or hardware-attestation claims without an explicit T3N attestation artifact.

## Security claims matrix

| Claim | Current status | Source of truth |
|---|---|---|
| Tenant DID derives from authenticated T3N session | PROVED LOCAL | gateway session code/tests |
| Agent uses separate credential/DID | PROVED LOCAL | agent/tenant session separation |
| Delegated calls bind `pii_did` to tenant DID | PROVED LOCAL | gateway contract tests |
| Secret/undelegated-host proposals are denied | PROVED LOCAL | Rust adversarial tests |
| Excess non-secret fields produce `REDACT` | PROVED LOCAL | Rust policy tests |
| Persisted `DENY` cannot be human-authorized | PROVED LOCAL | Spring service tests |
| Protected remediation requires operator authorization | PROVED LOCAL | Spring service/security tests |
| Gateway remediation requires service auth + signed capability | PROVED LOCAL | gateway authorization boundary |
| Capability body tampering/expiry/replay is rejected | PROVED LOCAL | `remediation-authorization.test.ts` |
| Consumed nonce remains rejected after verifier restart using same replay store | PROVED LOCAL | persistent replay-store test |
| Secret/header reflection is not returned | PROVED LOCAL | Rust remediation regression |
| Revoked delegation blocks protected egress on testnet | NOT CLAIMED | only after matching live evidence |
| Full attack -> remediation run on testnet | NOT CLAIMED | only after matching live evidence |
| Hardware attestation for this execution | NOT CLAIMED | no explicit attestation artifact yet |

## Privileged remediation flow

```text
TEE policy ALLOW
      |
      v
Authenticated operator authorizes
      |
      v
Spring verifies persisted action + ALLOW
      |
      v
HMAC capability
  incident/action/decision/request
  action/resource/purpose/fieldsHash
  authorizedAt/expiresAt/nonce
      |
      v
Gateway verifies service token
      |
      v
Gateway verifies signature + exact body + expiry
      |
      v
Gateway consumes nonce in persistent replay store
      |
      v
T3N execute-remediation
```

`DENY` and `REDACT` never generate a valid execution path. Capability values, signing keys and service tokens must never appear in browser, logs, audit or evidence.

## Terminal 3 integration findings

### Member Delegation example and `scopes`
The current integration treats non-empty scopes as required because the field reference requires them even where simplified examples omit them. `DelegationService.grant` always validates/sends explicit scopes.

### Delegated `pii_did`
Authenticated agent identity identifies the caller, while `pii_did` identifies the tenant/data-owner authorization subject. Every delegated execution derives `pii_did` from `tenantSession.getTenantDid()`; browser/Java cannot override it.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.**

For handover, provision new tenant/agent credentials, rotate operator credentials, generate new `GATEWAY_SERVICE_TOKEN` and `REMEDIATION_CAPABILITY_KEY`, mount persistent gateway `/data`, register/resolve the intended contract version, seed private remediation configuration, create minimum delegation and run live evidence before production use. Existing private keys are never transferred through GitHub or the UI.

## Evidence model

```text
WASM bytes -> SHA-256 -> deployment-manifest.json
                         |
                         +-> same network/DIDs/contract/version/hash
                                      |
                                      v
                               testnet-run.json
```

`PASS` means observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means the scenario was not executed and is never counted as `PASS`.

### Local controls

```bash
bash scripts/run-local-evidence.sh
```

### Live testnet evidence

```bash
cd t3n-gateway
npm install
npm run evidence:live
```

Full synthetic egress remains opt-in through the documented evidence flags. The command must fail on scenario `FAIL`, identity/version/hash mismatch or detected secret material.

## Screenshot shot list

1. Operational T3N status with separate tenant/agent/contract/delegation states.
2. Unsafe proposal and `DENY`.
3. `REDACT` data-minimization evidence.
4. Safe remediation and `ALLOW`.
5. Human authorization displayed separately from execution.
6. One-time authorization proof state without exposing token/signature/nonce.
7. Protected remediation result only when synthetic egress actually succeeds.
8. Evidence Center with T3N_TESTNET metadata/results.

Never capture passwords, cookies, T3N private keys, service token, capability signing key/token, remediation key, `.env` or raw logs.

## Automated capture harness

From `frontend/`:

```bash
npm install
npx playwright install chromium
CAPTURE_BASE_URL='https://your-live-app.example' \
CAPTURE_OPERATOR_USERNAME='operator-name' \
CAPTURE_OPERATOR_PASSWORD='runtime-password' \
npm run capture:submission
```

Final capture is refused unless operational status and T3N_TESTNET evidence satisfy the existing harness checks. Protected remediation remains disabled unless `CAPTURE_ALLOW_REMEDIATION=true` is explicitly supplied for the documented synthetic host.

## Demo video storyboard

```text
0–15s    Problem: compromised agent should not become authority
15–35s   Show separate live tenant/agent/contract/delegation status
35–55s   Unsafe exfiltration proposal -> DENY
55–75s   Show minimization/REDACT evidence
75–100s  Legitimate minimum remediation -> ALLOW
100–125s Human authorization -> one-time bound proof
125–150s Synthetic protected execution when enabled
150–180s Evidence Center -> T3N_TESTNET proof metadata/results
```

## UX/claim wording rules

- **authenticated**: a session identity was authenticated;
- **resolved**: contract id/version were resolved;
- **delegated**: an active member grant was observed;
- **authorized**: human business authorization was persisted;
- **execution proof**: short-lived server-to-gateway capability, not hardware attestation;
- **executed**: the operation actually ran;
- **proved live**: matching live evidence exists;
- **secretless from application/agent layers**: the secret is not exposed to browser, Java or agent; it still exists in protected storage.

Do not say “guarantees GDPR compliance” or “hardware verified” without corresponding evidence.

This file is the repository source of truth for the public submission narrative and handover model.
