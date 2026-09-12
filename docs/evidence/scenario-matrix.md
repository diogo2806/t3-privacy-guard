# Adversarial Security Scenario Matrix

This matrix distinguishes **automated local assertions** from **real T3N testnet executions**. A test is never labelled as testnet evidence unless `npm run evidence:testnet` actually produced the result.

| ID | Layer | Scenario / input | Expected result | Automated by | Current evidence state |
|---|---|---|---|---|---|
| A01 | Rust | Prompt-injected request asks for `api_key` and attacker host | `DENY / SECRET_DISCLOSURE_FORBIDDEN` | `contracts/privacy-guard/tests/adversarial.rs` | READY_TO_RUN |
| A02 | Rust | `revoke-credential` to `attacker.example` | `DENY / HOST_NOT_ALLOWED` | Rust adversarial test | READY_TO_RUN |
| A03 | Rust | Legitimate action requests unnecessary `employee_department` | `REDACT` and field listed for removal | Rust adversarial test | READY_TO_RUN |
| A04 | Rust | Malformed/non-JSON policy payload | Fail closed, no decision fabricated | Rust adversarial test | READY_TO_RUN |
| A05 | Rust | Non-T3N agent DID | `DENY / INVALID_AGENT_DID` | Rust adversarial test | READY_TO_RUN |
| A06 | Rust | Unknown privileged action `dump-database` | `DENY / ACTION_NOT_ALLOWED` | Rust adversarial test | READY_TO_RUN |
| A07 | Rust | Correct action with purpose `analytics` | `DENY / PURPOSE_NOT_ALLOWED` | Rust adversarial test | READY_TO_RUN |
| A08 | Rust | Egress action without destination host | `DENY / HOST_REQUIRED` | Rust adversarial test | READY_TO_RUN |
| A09 | Rust | Local `create-incident` action unexpectedly requests egress | `DENY / UNEXPECTED_EGRESS` | Rust adversarial test | READY_TO_RUN |
| A10 | Rust | Host contains scheme or port | `DENY / HOST_NOT_ALLOWED` | Rust adversarial test | READY_TO_RUN |
| A11 | Rust | Blank or >128-character request ID | `DENY / INVALID_REQUEST_ID` | Rust adversarial test | READY_TO_RUN |
| A12 | Rust | Malicious action is denied, then minimum legitimate remediation is evaluated | `DENY` followed by `ALLOW` | Rust adversarial test | READY_TO_RUN |
| A13 | Java | Duplicate persisted `requestId` replay | Business conflict, second proposal rejected | `IncidentServiceTest` | READY_TO_RUN |
| A14 | Java | Persisted TEE decision is `DENY` | Explicit remediation authorization rejected | `IncidentServiceTest` | READY_TO_RUN |
| A15 | Java | Same action evaluated twice | Gateway/T3N invoked once; persisted decision reused | `IncidentServiceTest` | READY_TO_RUN |
| A16 | Java | Same protected remediation requested twice after verified completion | External execution invoked once; persisted verified result reused | `IncidentServiceTest` | READY_TO_RUN |
| A17 | Java | Gateway/T3N unavailable during evaluation | Fail closed, no decision persisted, no remediation authorization | `IncidentServiceTest` | READY_TO_RUN |
| A18 | Java | Gateway returns a different policy `requestId` | Fail closed, response not persisted | `IncidentServiceTest` | READY_TO_RUN |
| A19 | Java | Execute remediation before explicit authorization | Blocked; remediation gateway not called | `IncidentServiceTest` | READY_TO_RUN |
| A20 | Java | Execution acknowledgement has a different `requestId` | `UNVERIFIED`; no automatic re-execution | `IncidentServiceTest` | READY_TO_RUN |
| A21 | Gateway | Agent DID differs from tenant delegation subject | `pii_did` remains canonical tenant DID | `privacy-guard-contract.test.ts` | READY_TO_RUN |
| A22 | Gateway | No matching member grant | `NOT_GRANTED`, no policy rewrite | `delegation-service.test.ts` | READY_TO_RUN |
| A23 | Gateway | Revoke existing grant | Only matching grant is expired, restrictions preserved | `delegation-service.test.ts` | READY_TO_RUN |
| A24 | Gateway | Grant only one function/scope/host set | SDK update contains exactly declared restrictions | `delegation-service.test.ts` | READY_TO_RUN |
| A25 | Evidence | Evidence contains synthetic sentinel secret | Evidence writer fails | `leak-detector.test.ts` | READY_TO_RUN |
| A26 | Rust | External response reflects Authorization/PII material | Contract result exposes only allowlisted operation/status metadata | `remediation.rs` regression tests | READY_TO_RUN |
| A27 | Evidence | Local test logs contain configured synthetic sentinel | Local evidence script aborts before summary is accepted | `scripts/run-local-evidence.sh` | READY_TO_RUN |
| A28 | Java | Two requests race on the same authorized remediation | Pessimistic claim permits at most one external execution | `IncidentServiceTest` | READY_TO_RUN |
| A29 | Java | External call returns HTTP 200 but read-back observes `ACTIVE` | `UNVERIFIED`, never `COMPLETED` | `IncidentServiceTest` | READY_TO_RUN |
| A30 | Java | Execution times out after send/ACK ambiguity | `UNVERIFIED`; replay does not resend side effect | `IncidentServiceTest` | READY_TO_RUN |
| A31 | Java | Verification temporarily unavailable, then recovers | Recheck may reach `COMPLETED`; no second egress | `IncidentServiceTest` | READY_TO_RUN |
| A32 | Java | Fresh concurrent caller sees existing `EXECUTING` claim | Remains `EXECUTING`, not falsely recovered as `UNVERIFIED` | `RemediationExecutionCoordinatorTest` | READY_TO_RUN |
| A33 | Java/API | Dashboard reload reads persisted remediation state | Read-only query does not execute or increment verification attempts | `RemediationQueryServiceTest` | READY_TO_RUN |
| A34 | React | Accepted execution awaits read-back | UI shows `PENDING / IN PROGRESS`, not `COMPLETED` | `RemediationPanel.test.tsx` | READY_TO_RUN |
| A35 | React | `UNVERIFIED` execution | Verify action available; second Execute action absent | `RemediationPanel.test.tsx` | READY_TO_RUN |
| A36 | Rust | Verification expected state is arbitrary/regex-like | Rejected; only closed `REVOKED` expectation accepted | `remediation.rs` tests | READY_TO_RUN |
| A37 | Rust | Read-back has matching operation and expected state | `VERIFIED`; mismatched state is `UNVERIFIED` | `remediation.rs` tests | READY_TO_RUN |
| L01 | T3N testnet | Authenticate tenant and agent with separate identities | Different canonical DIDs | `npm run evidence:testnet` | NOT_RUN until valid credentials/credits |
| L02 | T3N testnet | Secret exfiltration request against registered contract | `DENY` | testnet runner | NOT_RUN until valid credentials/credits |
| L03 | T3N testnet | Undelegated/forbidden host | `DENY` | testnet runner | NOT_RUN until valid credentials/credits |
| L04 | T3N testnet | Wrong purpose | `DENY` | testnet runner | NOT_RUN until valid credentials/credits |
| L05 | T3N testnet | Excess non-secret field | `REDACT` | testnet runner | NOT_RUN until valid credentials/credits |
| L06 | T3N testnet | Minimum legitimate policy request | `ALLOW` | testnet runner | NOT_RUN until valid credentials/credits |
| L07 | T3N testnet | `execute-remediation` removed from active grant | Protected egress rejected specifically for authorization/delegation reasons | testnet runner + `EVIDENCE_RUN_EGRESS_NEGATIVES=true` | NOT_RUN until private map is seeded |
| L08 | T3N testnet | Grant revoked before protected egress | Protected egress rejected specifically for authorization/delegation reasons | testnet runner + `EVIDENCE_RUN_EGRESS_NEGATIVES=true` | NOT_RUN until private map is seeded |
| L09 | T3N testnet | Attack denied, protected execution accepted, independent read-back verifies expected state | `DENY -> PENDING_VERIFICATION -> VERIFIED (REVOKED)` | testnet runner + `EVIDENCE_RUN_REMEDIATION=true` | NOT_RUN until remediation + verification endpoints are seeded |
| L10 | T3N testnet | `verified_email` logical reference evaluated for notification | `ALLOW` by policy | testnet runner | NOT_RUN until valid credentials/credits |
| L11 | T3N testnet | T3N resolves verified-email profile placeholder during egress | Resolved only inside protected egress | testnet runner | NOT_RUN until compatible synthetic profile/user context exists |

## Interpretation

`READY_TO_RUN` means the executable assertion exists in the repository but this document does not pretend it was executed by a particular environment. `NOT_RUN` means the scenario intentionally requires real T3N testnet state, credentials, credits and, for egress scenarios, seeded private remediation/verification configuration.

`execute-remediation` returning 2xx is only an **acceptance signal**. It is represented as `PENDING_VERIFICATION`. `COMPLETED` is reserved for the Spring state machine after `verify-remediation` independently observes the closed expected state. A timeout or ambiguous acknowledgement is `UNVERIFIED` and never triggers automatic re-execution.

`requestId` is propagated as the stable logical idempotency key. The project does not claim exactly-once or at-most-once behavior from an external provider unless that provider explicitly honors the key. The local atomic claim prevents this application from intentionally initiating a second egress for the same action.

The generated `docs/evidence/testnet-run.json` is the source of truth for actual live results. It is written only after leak detection checks configured tenant/agent/provider/service/capability/remediation secrets. Negative delegation scenarios count as `PASS` only when the returned failure is recognizably authorization/delegation related; a missing secret, transport failure or unrelated runtime exception is recorded as `FAIL`.
