# Security API contract

guard-runtime performs remediation by calling a **security API**: a service you run in front of your own tooling
(identity provider, credential vault, ticketing, messaging). This page is everything that service has to implement.
The app ships a reference implementation, the built-in adapter at `/api/security/remediation/{execute,verify}`
(`backend/.../service/SecurityRemediationAdapterService.java`), which the local stack and the end-to-end check use.

Configure it in guard-runtime:

```env
SECURITY_API_URL=https://security.example.com/remediation/execute
SECURITY_VERIFICATION_URL=https://security.example.com/remediation/verify
SECURITY_API_KEY=<random secret, 32+ characters>
```

The hostname of `SECURITY_API_URL` must be in the policy's `allowed_hosts` for each remediation action. HTTPS and no
explicit port are required (unless `GUARD_RUNTIME_ALLOW_INSECURE_HTTP=true`, for local development only).

## Common rules

- Both calls are `POST` with `Content-Type: application/json`, `Accept: application/json` and
  `Authorization: Bearer <SECURITY_API_KEY>`. Reject anything else with `401`.
- Bodies are flat JSON objects with string values.
- guard-runtime does not follow redirects, waits at most `GUARD_RUNTIME_EGRESS_TIMEOUT_MS` (15 s by default) and reads
  at most 64 KiB of the response.
- Any status outside 2xx is a failure. An execution that fails after the request was sent is recorded as
  `UNVERIFIED` and **never retried automatically**; an operator decides what happens next.
- Return only what is listed below. guard-runtime ignores every other field, so private values echoed back never reach
  the app.

## Execute

```http
POST {SECURITY_API_URL}
Authorization: Bearer <SECURITY_API_KEY>
Idempotency-Key: <request_id>
Content-Type: application/json

{
  "request_id": "inc-2026-0042-revoke-1",
  "action": "revoke-credential",
  "resource": "credential:cred-42",
  "purpose": "incident-remediation",
  "incident_id": "6f1c...",
  "credential_id": "cred-42",
  "reason": "Credential found in a public paste"
}
```

- `request_id`, `action`, `resource` and `purpose` are always present. The other keys are the **trusted values the
  policy allowed**, after minimization: a field the policy redacted is not sent at all.
- `Idempotency-Key` equals `request_id`. Treat a repeated key as the same operation and return the same
  `operation_id`, without acting twice. Exactly-once behaviour depends on you honouring it.
- Respond `2xx` (`202` is typical) once the action is accepted:

```json
{ "operation_id": "op-7f3a9c" }
```

`operation_id` must match `[A-Za-z0-9][A-Za-z0-9_-]{0,127}`; anything else is discarded, and the operation can then
never be verified.

### Actions

| `action` | `purpose` | Normal fields | Private value | Expected state after completion |
|---|---|---|---|---|
| `revoke-credential` | `incident-remediation` | `incident_id`, `credential_id`, `reason` | none | `REVOKED` |
| `notify-security` | `incident-notification` | `incident_id`, `severity`, `summary` | `recipient` | `DELIVERED` |

For `notify-security`, guard-runtime adds `recipient` with the verified security contact (`GUARD_RUNTIME_VERIFIED_EMAIL`).
That is the only place the address exists outside guard-runtime: do not log it, and do not return it.

## Verify

guard-runtime calls this after an accepted execution, and again whenever an operator asks to re-verify. Answer from
the real state of the target system, not from your record of having sent a request.

```http
POST {SECURITY_VERIFICATION_URL}
Authorization: Bearer <SECURITY_API_KEY>
Content-Type: application/json

{
  "request_id": "inc-2026-0042-revoke-1",
  "operation_id": "op-7f3a9c",
  "action": "revoke-credential",
  "expected_state": "REVOKED"
}
```

Respond `2xx`:

```json
{ "operation_id": "op-7f3a9c", "state": "REVOKED" }
```

| Field | Meaning |
|---|---|
| `operation_id` | The same id; a different one leaves the remediation `UNVERIFIED` |
| `state` | The observed state. Only the exact expected state (`REVOKED`, `DELIVERED`) completes the remediation; report anything else (`ACTIVE`, `PENDING`, `FAILED`...) honestly |
| `recipient_resolved` | `notify-security` only: `true` when the message reached a real recipient. Required for completion |

## Checklist for a new integration

1. Create the two endpoints with the bearer check, the idempotency rule and the responses above.
2. Make verification read the target system (is the credential really revoked? was the message delivered?).
3. Put the endpoint URLs and key in guard-runtime, and the hostname in the policy (dashboard **Policy** tab).
4. Run one revocation and one notification from the dashboard; the remediation panel must reach `COMPLETED`, and the
   status bar must show the integration as ready.
