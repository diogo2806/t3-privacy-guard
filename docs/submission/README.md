# T3 Privacy Guard — Submission & Judge Guide

## Executive summary

T3 Privacy Guard assumes the AI agent itself can be manipulated. The demo sends a real textual prompt to a configured tool-calling model. The model may propose an unsafe action, but its tool surface contains only `action`, `resource`, `purpose`, optional `host` and `fields`. It cannot provide a policy decision, DID, override, secret or execution capability.

The structured proposal is persisted and sent to the independent Terminal 3 Rust/WASM policy through the authenticated Agent DID and tenant `pii_did`. A malicious exfiltration proposal receives `DENY`. A minimum legitimate proposal can receive `ALLOW`, but `ALLOW` is still not execution: an authenticated operator must explicitly authorize remediation, after which Spring emits a short-lived one-time signed capability bound to the exact action and decision. The gateway verifies service authentication, capability integrity, expiry, body equality and anti-replay state before protected T3N execution.

The project reports only verifiable state: `NOT_RUN` never becomes `PASS`, simulated output is not labelled live, and hardware attestation is not claimed without a concrete artifact.

## Judge quick path

```text
1. Sign in as application operator
2. Confirm Gateway / Tenant / Agent / Contract / Delegation separately
3. Inspect the attack prompt
4. Click Run attack scenario
5. Inspect the real model's structured Agent proposal
6. Observe independent T3N TEE DENY
7. Load a safe prompt and Ask agent, or prepare the known minimum remediation
8. Observe T3N ALLOW
9. Record explicit human authorization
10. Execute protected remediation when synthetic egress is enabled
11. Open Evidence and confirm T3N_TESTNET metadata/results
```

## Architecture and trust boundaries

```text
Untrusted prompt
      |
      v
AI provider (proposal only)
      |
      v
Browser / Spring Boot
      |
      | service-authenticated internal call
      v
T3N Gateway
      | authenticated Agent DID + tenant pii_did
      v
T3N / Rust WASM policy
   DENY | REDACT | ALLOW
                    |
            authenticated human
                    |
             one-time capability
                    |
             protected execution
```

Trust model:

- **Prompt is untrusted.** It may contain instruction injection. The prompt never becomes an authorization source.
- **The model is not a security boundary.** It can only call one proposal tool with a closed JSON schema.
- **Unknown or privileged model fields are rejected.** `decision`, `allow`, `override`, `approved`, `agent_did`, `pii_did`, credential/secret/API-key fields and unknown keys are rejected before T3N evaluation.
- **T3N identities are server-derived.** Agent DID comes from the authenticated agent session; tenant `pii_did` from the authenticated tenant session. Neither comes from the LLM/browser.
- **Rust/WASM owns the policy decision.** The model cannot manufacture `ALLOW`.
- **Spring Boot owns durable business authorization.** It persists incident/action/decision state and creates a remediation capability only after a persisted `ALLOW` plus explicit human authorization.
- **Gateway owns T3N sessions and privileged execution.** It requires a separate service token and validates/consumes the one-time capability before remediation.
- **Private KV owns remediation credentials.** The protected secret is not returned to browser, Java or the model.

The current prompt path is for sanitized/non-secret incident instructions. Real private profile values are intentionally not placed in model prompts; issue #37 moves private data use to T3N profile references resolved only at protected egress.

## Security claims matrix

| Claim | Current status | Source of truth |
|---|---|---|
| Real configured model produces the structured proposal path | PROVED LOCAL | provider adapter + agent service + backend orchestration tests |
| Tool schema cannot accept decision/override/DID/secret authority fields | PROVED LOCAL | `proposal-schema.test.ts` |
| Disabled AI provider fails closed | PROVED LOCAL | `agent-service.test.ts` |
| Malicious model proposal is independently persisted/evaluated and can be DENY | PROVED LOCAL | `AgentAnalysisServiceTest` + Rust policy tests |
| Legitimate model proposal can receive ALLOW without auto-execution | PROVED LOCAL | `AgentAnalysisServiceTest` |
| Tenant DID derives from authenticated T3N session | PROVED LOCAL | gateway session code/tests |
| Agent uses separate credential/DID | PROVED LOCAL | agent/tenant session separation |
| Delegated calls bind `pii_did` to tenant DID | PROVED LOCAL | gateway contract tests |
| Protected remediation requires service auth + signed human capability | PROVED LOCAL | gateway authorization boundary/tests |
| Capability body tampering/expiry/replay is rejected | PROVED LOCAL | remediation authorization tests |
| Secret/header reflection is not returned | PROVED LOCAL | Rust remediation regression |
| Real model attack -> T3N DENY on live testnet | NOT CLAIMED | becomes live only when a matching public capture/evidence run exists |
| Revoked delegation blocks protected egress on live testnet | NOT CLAIMED | only after matching live evidence |
| Hardware attestation for this execution | NOT CLAIMED | no explicit attestation artifact yet |

## Real AI tool boundary

The provider adapter uses a single forced tool:

```json
{
  "action": "string",
  "resource": "string",
  "purpose": "string",
  "host": "string|null",
  "fields": ["string"]
}
```

The provider is configured only by runtime environment:

```text
AI_PROVIDER=openai-compatible
AI_API_URL=<chat-completions compatible endpoint>
AI_API_KEY=<runtime secret>
AI_MODEL=<tool-calling model>
```

`AI_PROVIDER=disabled` is the safe default. Disabled/unavailable provider, invalid JSON, missing/multiple tool calls, extra fields or unsafe authority fields fail closed. A demo fixture is never relabelled as live AI.

## Privileged remediation flow

```text
T3N TEE ALLOW
      |
Authenticated operator authorizes
      |
Spring checks persisted action + ALLOW
      |
HMAC one-time capability
      |
Gateway verifies service token + signature + exact body + expiry
      |
Gateway consumes persistent nonce
      |
T3N execute-remediation
```

`DENY` and `REDACT` do not produce a valid privileged execution path.

## Terminal 3 integration findings

### Member Delegation example and `scopes`
The project validates/sends non-empty scopes even where simplified examples omit them, following the field reference.

### Delegated `pii_did`
Every delegated execution derives `pii_did` internally from `tenantSession.getTenantDid()`. Browser, Java and LLM cannot supply or override the authorization subject.

## Post-challenge operation and handover

**Decision: continue running the project after the challenge.** Future handover provisions new tenant/agent credentials, operator credentials, provider key, `GATEWAY_SERVICE_TOKEN` and `REMEDIATION_CAPABILITY_KEY`; existing private keys are not transferred through GitHub/UI. Persistent gateway `/data` is mounted for anti-replay state.

## Evidence model

```text
WASM bytes -> SHA-256 -> deployment-manifest.json
                         |
                         +-> same DIDs / contract / version / hash
                                      |
                                      v
                               testnet-run.json
```

`PASS` means the observed result matched expectation. `FAIL` means it did not. `NOT_RUN` means the scenario was not executed and is never counted as success.

### Local controls

```bash
bash scripts/run-local-evidence.sh
```

### Live T3N evidence

```bash
cd t3n-gateway
npm install
npm run evidence:live
```

The capture harness requires real T3N evidence before final capture. Its attack screenshot now also requires the visible `Agent proposal` produced through the actual `/api/agent/analyze` path. Capture metadata is leak-scanned for operator credentials, T3N keys, AI provider key, service token, capability signing key, remediation key and configured sentinel.

## Screenshot shot list

1. Live T3N operational status.
2. Attack prompt + provider/model provenance + model proposal + `DENY`.
3. `REDACT` data-minimization evidence.
4. Legitimate proposal/minimum remediation + `ALLOW`.
5. Human authorization separate from execution.
6. One-time authorization state without token/signature/nonce.
7. Protected result only when synthetic egress actually succeeds.
8. Evidence Center with T3N_TESTNET metadata/results.

Never capture passwords, cookies, T3N keys, provider key, internal service token, capability signing key/token, remediation secret, `.env` or raw logs.

## Demo video storyboard

```text
0–15s    Problem: the model itself may be manipulated
15–35s   Show live tenant/agent/contract/delegation identities
35–60s   Show attack prompt -> real provider -> structured Agent proposal
60–80s   Show independent T3N TEE DENY
80–105s  Safe prompt/minimum proposal -> ALLOW
105–130s Human authorization -> one-time bound proof
130–155s Synthetic protected execution when enabled
155–180s Evidence Center -> T3N_TESTNET metadata/results
```

## UX/claim wording rules

- **agent proposal**: model-produced structured request, not an authorization;
- **authenticated**: a session identity was authenticated;
- **resolved**: contract id/version were resolved;
- **delegated**: an active member grant was observed;
- **authorized**: human business authorization was persisted;
- **execution proof**: short-lived server-to-gateway capability, not hardware attestation;
- **executed**: operation actually ran;
- **proved live**: matching live evidence/capture exists;
- **secretless from application/agent layers**: secret is not exposed to browser, Java or model; it still exists in protected storage.

Do not say “guarantees GDPR compliance” or “hardware verified” without corresponding evidence.

This file is the repository source of truth for the public submission narrative and handover model.
