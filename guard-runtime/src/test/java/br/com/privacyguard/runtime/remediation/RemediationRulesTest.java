package br.com.privacyguard.runtime.remediation;

import static br.com.privacyguard.runtime.remediation.RemediationRules.VERIFIED_EMAIL_MARKER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.policy.AppliedPolicy;
import br.com.privacyguard.runtime.policy.PolicyDecision;
import br.com.privacyguard.runtime.policy.PolicyDecision.Decision;
import br.com.privacyguard.runtime.policy.PolicyDocument;
import br.com.privacyguard.runtime.policy.PolicyEvaluator;
import br.com.privacyguard.runtime.remediation.RemediationVerificationResult.PayloadMinimizationProof;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;

/** Port of the unit tests in remediation.rs. */
class RemediationRulesTest {
    private static final String EXECUTOR = "agent:executor";
    private static final Predicate<String> IS_EXECUTOR = EXECUTOR::equals;
    private static final Predicate<String> IS_PROPOSAL_AGENT = "agent:proposal"::equals;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static AppliedPolicy appliedPolicy() {
        TreeMap<String, PolicyDocument.ActionPolicy> actions = new TreeMap<>();
        actions.put("revoke-credential", new PolicyDocument.ActionPolicy("incident-remediation",
            List.of("credential_id", "incident_id", "reason"), List.of("postman-echo.com"), List.of(), true, true));
        actions.put("notify-security", new PolicyDocument.ActionPolicy("incident-notification",
            List.of("incident_id", "severity", "summary"), List.of("postman-echo.com"), List.of("verified_email"), true, true));
        return new AppliedPolicy(new PolicyDocument("2026-09-12.1", actions), "2026-09-12.1", "a".repeat(64));
    }

    static Request executionRequest() {
        return new Request();
    }

    static Request notificationExecutionRequest() {
        Request request = new Request();
        request.requestId = "r2";
        request.action = "notify-security";
        request.resource = "incident:test";
        request.purpose = "incident-notification";
        request.fields = List.of("incident_id", "severity", "summary");
        request.normalPayload = new TreeMap<>(Map.of("incident_id", "inc-demo-001", "severity", "critical", "summary", "synthetic security incident"));
        request.privateRefs = List.of("verified_email");
        return request;
    }

    @Test
    void mapsOnlyVerifiedEmailToTheProfileMarker() {
        assertThat(RemediationRules.profileMarker("verified_email")).isEqualTo(VERIFIED_EMAIL_MARKER);
        assertThatThrownBy(() -> RemediationRules.profileMarker(VERIFIED_EMAIL_MARKER)).isInstanceOf(ContractRejectedException.class);
        assertThatThrownBy(() -> RemediationRules.profileMarker("unknown_private_value")).isInstanceOf(ContractRejectedException.class);
    }

    @Test
    void notifySecurityRequiresTheExactLogicalPrivateReferenceAndPurpose() {
        RemediationRules.validateExecutionRequest(notificationExecutionRequest().build(), IS_EXECUTOR);
        Request missingRef = notificationExecutionRequest();
        missingRef.privateRefs = List.of();
        assertRejected(() -> RemediationRules.validateExecutionRequest(missingRef.build(), IS_EXECUTOR), "verified_email");
        Request literalMarker = notificationExecutionRequest();
        literalMarker.privateRefs = List.of(VERIFIED_EMAIL_MARKER);
        assertRejected(() -> RemediationRules.validateExecutionRequest(literalMarker.build(), IS_EXECUTOR), "verified_email");
        Request wrongPurpose = notificationExecutionRequest();
        wrongPurpose.purpose = "analytics";
        assertRejected(() -> RemediationRules.validateExecutionRequest(wrongPurpose.build(), IS_EXECUTOR), "verified_email");
    }

    @Test
    void remediationRequiresTheExactAuthorizedPolicyVersionAndHash() {
        RemediationRules.validatePolicyBinding(executionRequest().build(), appliedPolicy());
        Request changed = executionRequest();
        changed.policyHash = "b".repeat(64);
        assertRejected(() -> RemediationRules.validatePolicyBinding(changed.build(), appliedPolicy()), "active policy changed");
    }

    @Test
    void approvedDestinationMustMatchTheResolvedExecutionHost() {
        assertThat(RemediationRules.ensureExecutionDestination("postman-echo.com", "postman-echo.com")).isEqualTo("postman-echo.com");
        assertThat(RemediationRules.ensureExecutionDestination("POSTMAN-ECHO.COM", "postman-echo.com")).isEqualTo("postman-echo.com");
        assertRejected(() -> RemediationRules.ensureExecutionDestination("security-a.example", "security-b.example"), "EXECUTION_DESTINATION_CHANGED");
        assertThat(RemediationRules.extractEgressHost("https://postman-echo.com/post", false)).isEqualTo("postman-echo.com");
        assertRejected(() -> RemediationRules.extractEgressHost("https://postman-echo.com:443/post", false), "invalid host");
        assertRejected(() -> RemediationRules.canonicalizeApprovedHost("https://postman-echo.com/post"), "not a valid hostname");
    }

    @Test
    void exactAllowedNormalPayloadIsMaterializedForEgress() {
        RemediationRules.MinimizedEgress egress = build(executionRequest());
        assertThat(egress.effectiveRequest().fields()).containsExactly("credential_id", "incident_id", "reason");
        assertThat(egress.body()).containsEntry("incident_id", "inc-demo-001")
            .containsEntry("credential_id", "cred-demo-001")
            .containsEntry("reason", "suspected compromise");
    }

    @Test
    void notificationCombinesMinimizedNormalValuesWithPrivatePlaceholderOnlyInsideEgress() {
        RemediationRules.MinimizedEgress egress = build(notificationExecutionRequest());
        assertThat(egress.effectiveRequest().privateRefs()).containsExactly("verified_email");
        assertThat(egress.body()).containsEntry("incident_id", "inc-demo-001")
            .containsEntry("severity", "critical")
            .containsEntry("summary", "synthetic security incident")
            .containsEntry("recipient", VERIFIED_EMAIL_MARKER);
    }

    @Test
    void redactedNormalValueNeverEntersTheEgressBody() {
        Request request = executionRequest();
        request.fields = List.of("incident_id", "credential_id", "reason", "employee_department");
        request.normalPayload.put("employee_department", "finance");
        PolicyDecision initial = PolicyEvaluator.evaluate(
            RemediationRules.originalPolicyRequest(request.build(), "postman-echo.com"), appliedPolicy(), IS_PROPOSAL_AGENT);
        assertThat(initial.decision()).isEqualTo(Decision.REDACT);
        assertThat(initial.redactedFields()).containsExactly("employee_department");

        RemediationRules.MinimizedEgress egress = build(request);
        assertThat(PolicyEvaluator.evaluate(egress.effectiveRequest(), appliedPolicy(), IS_PROPOSAL_AGENT).decision()).isEqualTo(Decision.ALLOW);
        assertThat(egress.body()).doesNotContainKey("employee_department").containsEntry("reason", "suspected compromise");
    }

    @Test
    void secretOrUnrequestedNormalPayloadFieldsFailBeforeEgress() {
        Request secret = executionRequest();
        secret.fields = List.of("incident_id", "credential_id", "reason", "api_key");
        secret.normalPayload.put("api_key", "synthetic-secret-must-not-egress");
        assertRejected(() -> RemediationRules.validateExecutionRequest(secret.build(), IS_EXECUTOR), "forbidden secret field");

        Request unrequested = executionRequest();
        unrequested.normalPayload.put("employee_department", "finance");
        assertRejected(() -> RemediationRules.validateExecutionRequest(unrequested.build(), IS_EXECUTOR), "was not requested");
    }

    @Test
    void boundedPayloadProofExposesOnlyBooleans() throws Exception {
        RemediationVerificationRequest request = new RemediationVerificationRequest("r1", "op-1", "revoke-credential", "REVOKED");
        String sentinel = "SENTINEL_MUST_NOT_LEAK_BACK";
        byte[] payload = """
            {"operation_id":"op-1","state":"REVOKED","payload_proof":{"must_egress_seen":true,"must_not_egress_seen":false},"debug":"%s"}"""
            .formatted(sentinel).getBytes(StandardCharsets.UTF_8);
        RemediationVerificationResult result = RemediationRules.verificationFromPayload(request, payload);
        assertThat(result.payloadProof()).isEqualTo(new PayloadMinimizationProof(true, false));
        assertThat(MAPPER.writeValueAsString(result)).doesNotContain(sentinel);
    }

    @Test
    void executionRejectsActionsWithoutAVerifiedCompletionContractBeforeEgress() {
        for (String action : List.of("isolate-account", "create-incident")) {
            Request request = executionRequest();
            request.action = action;
            assertThatThrownBy(() -> RemediationRules.validateExecutionRequest(request.build(), IS_EXECUTOR))
                .isInstanceOf(ContractRejectedException.class)
                .hasMessage("protected remediation executor is not implemented for this action");
        }
    }

    @Test
    void executionWithoutApprovedDestinationFailsClosed() {
        Request request = executionRequest();
        request.approvedHost = "";
        assertRejected(() -> RemediationRules.validateExecutionRequest(request.build(), IS_EXECUTOR), "approved remediation destination");
    }

    @Test
    void executionWithoutOneTimeAuthorizationProofFailsClosed() {
        Request request = executionRequest();
        request.authorizationProof = "";
        assertRejected(() -> RemediationRules.validateExecutionRequest(request.build(), IS_EXECUTOR), "one-time authorization proof");
    }

    @Test
    void verificationExpectedStateIsClosedPerAction() {
        RemediationRules.validateVerificationRequest(new RemediationVerificationRequest("r1", "op-1", "revoke-credential", "REVOKED"));
        RemediationRules.validateVerificationRequest(new RemediationVerificationRequest("r2", "op-2", "notify-security", "DELIVERED"));
        assertRejected(() -> RemediationRules.validateVerificationRequest(new RemediationVerificationRequest("r2", "op-2", "notify-security", "REVOKED")), "expected_state");
        assertRejected(() -> RemediationRules.validateVerificationRequest(new RemediationVerificationRequest("r1", "private@example.test", "revoke-credential", "REVOKED")), "safe opaque");
    }

    @Test
    void independentReadbackMustMatchOperationStateAndPrivateResolution() throws Exception {
        RemediationVerificationRequest revoke = new RemediationVerificationRequest("r1", "op-1", "revoke-credential", "REVOKED");
        RemediationVerificationResult verified = RemediationRules.verificationFromPayload(revoke,
            "{\"operation_id\":\"op-1\",\"state\":\"REVOKED\",\"secret\":\"do-not-return\"}".getBytes(StandardCharsets.UTF_8));
        assertThat(verified.status()).isEqualTo("VERIFIED");
        assertThat(verified.observedState()).isEqualTo("REVOKED");
        assertThat(verified.payloadProof()).isNull();

        RemediationVerificationRequest notify = new RemediationVerificationRequest("r2", "op-2", "notify-security", "DELIVERED");
        RemediationVerificationResult delivered = RemediationRules.verificationFromPayload(notify,
            "{\"operation_id\":\"op-2\",\"state\":\"DELIVERED\",\"recipient_resolved\":true,\"recipient\":\"private@example.test\"}".getBytes(StandardCharsets.UTF_8));
        assertThat(delivered.status()).isEqualTo("VERIFIED");
        assertThat(delivered.recipientResolved()).isTrue();
        RemediationVerificationResult unresolved = RemediationRules.verificationFromPayload(notify,
            "{\"operation_id\":\"op-2\",\"state\":\"DELIVERED\",\"recipient_resolved\":false}".getBytes(StandardCharsets.UTF_8));
        assertThat(unresolved.status()).isEqualTo("UNVERIFIED");
        String serialized = MAPPER.writeValueAsString(delivered);
        assertThat(serialized).doesNotContain("@").doesNotContain(VERIFIED_EMAIL_MARKER);
    }

    @Test
    void malformedInputFailsClosed() {
        assertThatThrownBy(() -> RemediationExecutionRequest.parse("bad".getBytes(StandardCharsets.UTF_8))).isInstanceOf(InvalidContractInputException.class);
    }

    @Test
    void reflectedUpstreamSecretOrPiiIsNotExposedByResultSchema() throws Exception {
        String sentinel = "SYNTHETIC_REFLECTED_PRIVATE_VALUE";
        byte[] payload = """
            {"operation_id":"operation-123","headers":{"authorization":"%1$s"},"body":"%1$s","recipient":"%1$s"}""".formatted(sentinel).getBytes(StandardCharsets.UTF_8);
        RemediationResult result = new RemediationResult("r2", "PENDING_VERIFICATION", 200, RemediationRules.extractOperationId(payload), "2026-09-12.1", "a".repeat(64));
        String serialized = MAPPER.writeValueAsString(result);
        assertThat(result.operationId()).isEqualTo("operation-123");
        assertThat(serialized).doesNotContain(sentinel);
        assertThat(serialized.toLowerCase()).doesNotContain("recipient");
        assertThat(RemediationRules.extractOperationId("{\"operation_id\":\"private@example.test\",\"state\":\"DELIVERED\"}".getBytes(StandardCharsets.UTF_8))).isNull();
    }

    @Test
    void malformedUpstreamBodyDoesNotEscapeRawContent() {
        assertThat(RemediationRules.extractOperationId("not-json".getBytes(StandardCharsets.UTF_8))).isNull();
    }

    // --- Java runtime specifics ---

    @Test
    void executorMustBeTheAuthenticatedCaller() {
        Request request = executionRequest();
        request.executorId = "agent:someone-else";
        assertRejected(() -> RemediationRules.validateExecutionRequest(request.build(), IS_EXECUTOR), "protected executor");
    }

    @Test
    void reEvaluationRequiresAConfiguredProposalAgent() {
        Request request = executionRequest();
        request.agentId = "agent:unknown";
        assertRejected(() -> build(request), "remediation denied: INVALID_AGENT_DID");
    }

    @Test
    void plainHttpEgressOnlyWhenExplicitlyAllowed() {
        assertRejected(() -> RemediationRules.extractEgressHost("http://security-api.internal/execute", false), "must use https");
        assertThat(RemediationRules.extractEgressHost("http://security-api.internal/execute", true)).isEqualTo("security-api.internal");
        // Explicit ports are a local-development convenience only; production keeps the contract's strict rule.
        assertThat(RemediationRules.extractEgressHost("http://localhost:8080/execute", true)).isEqualTo("localhost");
        assertRejected(() -> RemediationRules.extractEgressHost("https://localhost:8443/execute", false), "invalid host");
    }

    private static RemediationRules.MinimizedEgress build(Request request) {
        return RemediationRules.buildMinimizedEgress(request.build(), appliedPolicy(), "postman-echo.com", IS_EXECUTOR, IS_PROPOSAL_AGENT);
    }

    private static void assertRejected(Runnable call, String fragment) {
        assertThatThrownBy(call::run).isInstanceOf(ContractRejectedException.class).hasMessageContaining(fragment);
    }

    /** Mutable builder mirroring the Rust tests' struct update syntax. */
    static final class Request {
        String incidentId = "incident-1";
        String actionId = "action-1";
        String decisionId = "decision-1";
        String requestId = "r1";
        String agentId = "agent:proposal";
        String executorId = EXECUTOR;
        String action = "revoke-credential";
        String resource = "credential:test";
        String purpose = "incident-remediation";
        String approvedHost = "postman-echo.com";
        List<String> fields = List.of("incident_id", "credential_id", "reason");
        SortedMap<String, String> normalPayload = new TreeMap<>(Map.of("incident_id", "inc-demo-001", "credential_id", "cred-demo-001", "reason", "suspected compromise"));
        List<String> privateRefs = List.of();
        String policyVersion = "2026-09-12.1";
        String policyHash = "a".repeat(64);
        String authorizationProof = "v2.placeholder.signature";

        RemediationExecutionRequest build() {
            return new RemediationExecutionRequest(incidentId, actionId, decisionId, requestId, agentId, executorId, action, resource, purpose,
                approvedHost, fields, normalPayload, privateRefs, policyVersion, policyHash, authorizationProof);
        }
    }
}
