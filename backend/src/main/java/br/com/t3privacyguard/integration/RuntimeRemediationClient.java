package br.com.t3privacyguard.integration;

import br.com.t3privacyguard.integration.GuardRuntimeClient.Caller;
import br.com.t3privacyguard.security.ProtectedExecutorIdentity;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Protected execution and independent read-back on guard-runtime, always as the protected executor. guard-runtime
 * verifies and burns the one-time capability itself before any outbound call.
 */
@Component
public class RuntimeRemediationClient {
    private static final List<String> EXECUTOR_FUNCTIONS = List.of("execute-remediation", "verify-remediation");

    private final GuardRuntimeClient runtime;
    private final ObjectMapper mapper;

    public RuntimeRemediationClient(GuardRuntimeClient runtime, ObjectMapper mapper) {
        this.runtime = runtime;
        this.mapper = mapper;
    }

    /** The executor identity guard-runtime authenticates, which the capability must be bound to. */
    public String requireExecutorDid() {
        GuardRuntimeClient.Response response = runtime.get("/v1/caller", Caller.EXECUTOR);
        JsonNode body = response.body();
        if (!response.ok() || body == null) throw new TrustRuntimeUnavailableException("Protected executor identity is unavailable");
        String id = body.path("id").asText(null);
        boolean granted = EXECUTOR_FUNCTIONS.stream().allMatch(function -> containsText(body.path("functions"), function));
        if (!runtime.executorId().equals(id) || !ProtectedExecutorIdentity.isValid(id) || !granted) {
            throw new TrustRuntimeUnavailableException("Protected executor is not authenticated and granted");
        }
        return id;
    }

    public RemediationResult execute(RemediationRequest request, String capability) {
        if (capability == null || capability.isBlank()) throw new IllegalArgumentException("Remediation capability is required");
        if (request.approvedHost() == null || request.approvedHost().isBlank()) throw new IllegalArgumentException("Approved remediation destination is required");
        if (request.normalPayload() == null || request.normalPayload().isEmpty()) throw new IllegalArgumentException("Trusted normal remediation payload is required");
        if (request.operatorPrincipalHash() == null || !request.operatorPrincipalHash().matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Bound operator principal hash is required");
        }
        if (request.authorizationRecordedAt() <= 0) throw new IllegalArgumentException("Bound human authorization timestamp is required");

        String executorDid = requireExecutorDid();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("incident_id", request.incidentId());
        body.put("action_id", request.actionId());
        body.put("decision_id", request.decisionId());
        body.put("request_id", request.requestId());
        body.put("agent_did", runtime.proposalAgentId());
        body.put("executor_did", executorDid);
        body.put("action", request.action());
        body.put("resource", request.resource());
        body.put("purpose", request.purpose());
        body.put("approved_host", request.approvedHost());
        body.put("fields", request.fields());
        body.put("normal_payload", request.normalPayload());
        body.put("private_refs", request.privateRefs() == null ? List.of() : request.privateRefs());
        body.put("policy_version", request.policyVersion());
        body.put("policy_hash", request.policyHash());
        body.put("authorization_proof", capability);

        GuardRuntimeClient.Response response = runtime.post("/v1/functions/execute-remediation", Caller.EXECUTOR, body);
        if (response.status() == 422 && "EXECUTION_DESTINATION_CHANGED".equals(rejectionReason(response))) {
            throw new RemediationDestinationChangedException("Protected destination changed after human authorization");
        }
        if (!response.ok()) throw new TrustRuntimeUnavailableException("Protected remediation acceptance is unavailable (guard-runtime HTTP " + response.status() + ")");
        RemediationResult result = read(response, RemediationResult.class)
            .withActivity(response.activitySequence(), response.activityHash());
        if (!"PENDING_VERIFICATION".equals(result.status())) {
            throw new TrustRuntimeUnavailableException("guard-runtime returned an invalid remediation acceptance result");
        }
        if (!request.policyVersion().equals(result.policyVersion()) || !request.policyHash().equals(result.policyHash())) {
            throw new TrustRuntimeUnavailableException("guard-runtime remediation policy metadata does not match the approved decision");
        }
        return result;
    }

    public VerificationResult verify(String requestId, String operationId) {
        return verifyClosedState(requestId, operationId, "revoke-credential", "REVOKED");
    }

    public VerificationResult verifyDelivery(String requestId, String operationId) {
        return verifyClosedState(requestId, operationId, "notify-security", "DELIVERED");
    }

    private VerificationResult verifyClosedState(String requestId, String operationId, String action, String expectedState) {
        if (operationId == null || operationId.isBlank()) throw new IllegalArgumentException("operationId is required for verification");
        GuardRuntimeClient.Response response = runtime.post(
            "/v1/functions/verify-remediation",
            Caller.EXECUTOR,
            new VerificationRequest(requestId, operationId, action, expectedState)
        );
        if (!response.ok()) throw new TrustRuntimeUnavailableException("External remediation verification is unavailable (guard-runtime HTTP " + response.status() + ")");
        VerificationResult result = read(response, VerificationResult.class)
            .withActivity(response.activitySequence(), response.activityHash());
        if (!("VERIFIED".equals(result.status()) || "UNVERIFIED".equals(result.status()))) {
            throw new TrustRuntimeUnavailableException("guard-runtime returned an invalid verification result");
        }
        return result;
    }

    private <T> T read(GuardRuntimeClient.Response response, Class<T> type) {
        if (response.body() == null) throw new TrustRuntimeUnavailableException("guard-runtime returned an empty result");
        try {
            T value = mapper.treeToValue(response.body(), type);
            if (value == null) throw new TrustRuntimeUnavailableException("guard-runtime returned an empty result");
            return value;
        } catch (JsonProcessingException | IllegalArgumentException ex) {
            throw new TrustRuntimeUnavailableException("guard-runtime returned an invalid result", ex);
        }
    }

    private static String rejectionReason(GuardRuntimeClient.Response response) {
        return response.body() == null ? null : response.body().path("reason").asText(null);
    }

    private static boolean containsText(JsonNode array, String value) {
        if (array == null || !array.isArray()) return false;
        for (JsonNode item : array) if (value.equals(item.asText(null))) return true;
        return false;
    }

    public record RemediationRequest(
        @JsonProperty("incident_id") String incidentId,
        @JsonProperty("action_id") String actionId,
        @JsonProperty("decision_id") String decisionId,
        @JsonProperty("request_id") String requestId,
        String action,
        String resource,
        String purpose,
        @JsonProperty("approved_host") String approvedHost,
        List<String> fields,
        @JsonProperty("normal_payload") Map<String, String> normalPayload,
        @JsonProperty("private_refs") List<String> privateRefs,
        @JsonProperty("policy_version") String policyVersion,
        @JsonProperty("policy_hash") String policyHash,
        @JsonProperty("operator_principal_hash") String operatorPrincipalHash,
        @JsonProperty("authorization_recorded_at") long authorizationRecordedAt
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RemediationResult(
        @JsonProperty("request_id") String requestId,
        String status,
        @JsonProperty("http_code") int httpCode,
        @JsonProperty("operation_id") String operationId,
        @JsonProperty("policy_version") String policyVersion,
        @JsonProperty("policy_hash") String policyHash,
        @JsonProperty("activity_sequence") Long activitySequence,
        @JsonProperty("activity_hash") String activityHash
    ) {
        public RemediationResult(String requestId, String status, int httpCode, String operationId, String policyVersion, String policyHash) {
            this(requestId, status, httpCode, operationId, policyVersion, policyHash, null, null);
        }

        RemediationResult withActivity(Long sequence, String hash) {
            return new RemediationResult(requestId, status, httpCode, operationId, policyVersion, policyHash, sequence, hash);
        }
    }

    public record VerificationRequest(
        @JsonProperty("request_id") String requestId,
        @JsonProperty("operation_id") String operationId,
        String action,
        @JsonProperty("expected_state") String expectedState
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record VerificationResult(
        @JsonProperty("request_id") String requestId,
        String status,
        @JsonProperty("observed_state") String observedState,
        @JsonProperty("recipient_resolved") Boolean recipientResolved,
        @JsonProperty("activity_sequence") Long activitySequence,
        @JsonProperty("activity_hash") String activityHash
    ) {
        public VerificationResult(String requestId, String status, String observedState) {
            this(requestId, status, observedState, null, null, null);
        }

        public VerificationResult(String requestId, String status, String observedState, Boolean recipientResolved) {
            this(requestId, status, observedState, recipientResolved, null, null);
        }

        VerificationResult withActivity(Long sequence, String hash) {
            return new VerificationResult(requestId, status, observedState, recipientResolved, sequence, hash);
        }
    }
}
