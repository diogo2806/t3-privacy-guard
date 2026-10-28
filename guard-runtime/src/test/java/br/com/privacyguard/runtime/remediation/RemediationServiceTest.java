package br.com.privacyguard.runtime.remediation;

import static br.com.privacyguard.runtime.testing.CapabilityTokens.NOW;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.PUBLIC_KEY_SPKI;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.signedToken;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.withProof;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.privacyguard.runtime.authorization.RemediationAuthorizer;
import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.CallerRegistry;
import br.com.privacyguard.runtime.caller.GuardFunction;
import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.egress.EgressException;
import br.com.privacyguard.runtime.egress.ProtectedEgress;
import br.com.privacyguard.runtime.policy.AppliedPolicy;
import br.com.privacyguard.runtime.policy.PolicyDocumentParser;
import br.com.privacyguard.runtime.store.FileReplayStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** execute/verify end to end inside the runtime, with only the outbound HTTP replaced by a recorder. */
class RemediationServiceTest {
    private static final String POLICY = """
        {"version":"2026-10-28.1","actions":{
          "notify-security":{"purpose":"incident-notification","allowed_fields":["incident_id","severity","summary"],"allowed_hosts":["security-a.example"],"allowed_private_refs":["verified_email"],"requires_host":true,"requires_human_authorization":true},
          "revoke-credential":{"purpose":"incident-remediation","allowed_fields":["incident_id","credential_id","reason"],"allowed_hosts":["security-a.example"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}}}""";
    private static final AppliedPolicy APPLIED = PolicyDocumentParser.parse(POLICY.getBytes(StandardCharsets.UTF_8));
    private static final String CALLERS = """
        [{"id":"agent:proposal","token":"proposal-token-0123456789abcdef0123456789","functions":["evaluate-action"]},
         {"id":"agent:executor","token":"executor-token-0123456789abcdef0123456789","functions":["execute-remediation","verify-remediation"]}]""";
    private static final Caller EXECUTOR = new Caller("agent:executor", Set.of(GuardFunction.EXECUTE_REMEDIATION, GuardFunction.VERIFY_REMEDIATION));

    @TempDir
    Path temp;

    private final Map<String, String> secrets = new HashMap<>();
    private final List<Call> calls = new ArrayList<>();
    private ProtectedEgress.Response nextResponse;
    private EgressException nextFailure;
    private RemediationService service;

    record Call(String url, Map<String, String> headers, SortedMap<String, String> body) {}

    @BeforeEach
    void setUp() {
        secrets.put("security_api_url", "https://security-a.example/api/security/remediation/execute");
        secrets.put("security_verification_url", "https://security-a.example/api/security/remediation/verify");
        secrets.put("security_api_key", "remediation-api-key-0123456789abcdef");
        secrets.put("remediation_auth_active_key_id", "primary");
        secrets.put("remediation_auth_public_key_spki:primary", PUBLIC_KEY_SPKI);
        nextResponse = new ProtectedEgress.Response(202, "{\"operation_id\":\"op-123\"}".getBytes(StandardCharsets.UTF_8));
        nextFailure = null;
        ObjectMapper mapper = new ObjectMapper();
        ProtectedEgress recorder = (url, headers, body) -> {
            if (nextFailure != null) throw nextFailure;
            calls.add(new Call(url, headers, body));
            return nextResponse;
        };
        RemediationAuthorizer authorizer = new RemediationAuthorizer(key -> Optional.ofNullable(secrets.get(key)),
            new FileReplayStore(temp.resolve("replay.json").toString(), mapper));
        service = new RemediationService(authorizer, () -> Optional.of(POLICY.getBytes(StandardCharsets.UTF_8)),
            key -> Optional.ofNullable(secrets.get(key)), recorder, new CallerRegistry(CALLERS, mapper),
            Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC), false);
    }

    private static RemediationExecutionRequest revoke() {
        return new RemediationExecutionRequest("incident-1", "action-1", "decision-1", "request-1", "agent:proposal", "agent:executor",
            "revoke-credential", "credential:cred-42", "incident-remediation", "security-a.example",
            List.of("incident_id", "credential_id", "reason", "employee_department"),
            new TreeMap<>(Map.of("incident_id", "inc-7781", "credential_id", "cred-42", "reason", "suspected compromise", "employee_department", "finance")),
            List.of(), APPLIED.version(), APPLIED.hash(), "pending");
    }

    private static RemediationExecutionRequest notify(String purposeHost) {
        return new RemediationExecutionRequest("incident-1", "action-2", "decision-2", "request-2", "agent:proposal", "agent:executor",
            "notify-security", "incident:7781", "incident-notification", purposeHost,
            List.of("incident_id", "severity", "summary"),
            new TreeMap<>(Map.of("incident_id", "inc-7781", "severity", "critical", "summary", "credential leaked")),
            List.of("verified_email"), APPLIED.version(), APPLIED.hash(), "pending");
    }

    private static RemediationExecutionRequest authorized(RemediationExecutionRequest request, String nonce) {
        return withProof(request, signedToken(request, nonce));
    }

    @Test
    void executesTheMinimizedRemediationAndReturnsOnlyTheReducedResult() {
        RemediationResult result = service.execute(authorized(revoke(), "nonce-service-001"), EXECUTOR);

        assertThat(result).isEqualTo(new RemediationResult("request-1", "PENDING_VERIFICATION", 202, "op-123", APPLIED.version(), APPLIED.hash()));
        assertThat(calls).hasSize(1);
        Call call = calls.get(0);
        assertThat(call.url()).isEqualTo("https://security-a.example/api/security/remediation/execute");
        assertThat(call.headers()).containsEntry("Authorization", "Bearer remediation-api-key-0123456789abcdef")
            .containsEntry("Idempotency-Key", "request-1");
        assertThat(call.body()).containsOnlyKeys("request_id", "action", "resource", "purpose", "incident_id", "credential_id", "reason");
        assertThat(call.body()).doesNotContainValue("finance");
    }

    @Test
    void theSameCapabilityCannotBeUsedTwice() {
        RemediationExecutionRequest request = authorized(revoke(), "nonce-service-002");
        service.execute(request, EXECUTOR);
        assertRejected(() -> service.execute(request, EXECUTOR), "replay");
        assertThat(calls).hasSize(1);
    }

    @Test
    void destinationChangedAfterApprovalFailsBeforeEgress() {
        secrets.put("security_api_url", "https://security-b.example/execute");
        assertRejected(() -> service.execute(authorized(revoke(), "nonce-service-003"), EXECUTOR), "EXECUTION_DESTINATION_CHANGED");
        assertThat(calls).isEmpty();
    }

    @Test
    void policyChangedAfterAuthorizationFailsBeforeEgress() {
        RemediationExecutionRequest stale = revoke();
        stale = new RemediationExecutionRequest(stale.incidentId(), stale.actionId(), stale.decisionId(), stale.requestId(), stale.agentId(),
            stale.executorId(), stale.action(), stale.resource(), stale.purpose(), stale.approvedHost(), stale.fields(), stale.normalPayload(),
            stale.privateRefs(), "2026-09-01.1", "c".repeat(64), "pending");
        RemediationExecutionRequest signed = authorized(stale, "nonce-service-004");
        assertRejected(() -> service.execute(signed, EXECUTOR), "active policy changed");
        assertThat(calls).isEmpty();
    }

    @Test
    void notificationLeavesTheContractLayerWithThePlaceholderNotThePrivateValue() {
        service.execute(authorized(notify("security-a.example"), "nonce-service-005"), EXECUTOR);
        assertThat(calls.get(0).body()).containsEntry("recipient", RemediationRules.VERIFIED_EMAIL_MARKER);
    }

    @Test
    void egressFailuresMapToTheContractMessages() {
        nextResponse = new ProtectedEgress.Response(500, new byte[0]);
        assertRejected(() -> service.execute(authorized(revoke(), "nonce-service-006"), EXECUTOR), "remediation upstream returned HTTP 500");
        nextFailure = new EgressException(EgressException.Kind.PLACEHOLDER_UNKNOWN, "x");
        assertRejected(() -> service.execute(authorized(notify("security-a.example"), "nonce-service-007"), EXECUTOR), "required verified profile value is unavailable");
    }

    @Test
    void missingPrivateConfigurationFailsClosed() {
        secrets.remove("security_api_url");
        assertRejected(() -> service.execute(authorized(revoke(), "nonce-service-008"), EXECUTOR), "required private configuration security_api_url is missing");
        secrets.remove("remediation_auth_active_key_id");
        assertRejected(() -> service.execute(authorized(revoke(), "nonce-service-009"), EXECUTOR), "active verification key id is not provisioned");
    }

    @Test
    void verificationReadsBackIndependently() {
        nextResponse = new ProtectedEgress.Response(200, "{\"operation_id\":\"op-123\",\"state\":\"REVOKED\",\"echo\":\"x\"}".getBytes(StandardCharsets.UTF_8));
        RemediationVerificationResult result = service.verify(new RemediationVerificationRequest("request-1", "op-123", "revoke-credential", "REVOKED"));
        assertThat(result.status()).isEqualTo("VERIFIED");
        assertThat(calls.get(0).url()).endsWith("/verify");
        assertThat(calls.get(0).headers()).doesNotContainKey("Idempotency-Key");
        assertThat(calls.get(0).body()).containsOnlyKeys("request_id", "operation_id", "action", "expected_state");
    }

    private static void assertRejected(Runnable call, String fragment) {
        assertThatThrownBy(call::run).isInstanceOf(ContractRejectedException.class).hasMessageContaining(fragment);
    }
}
