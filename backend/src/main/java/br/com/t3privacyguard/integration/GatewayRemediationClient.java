package br.com.t3privacyguard.integration;

import br.com.t3privacyguard.observability.TraceContext;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

@Component
public class GatewayRemediationClient {
    private final RestClient restClient;
    private final String serviceToken;

    public GatewayRemediationClient(
        RestClient.Builder builder,
        @Value("${privacy-guard.gateway.base-url}") String baseUrl,
        @Value("${privacy-guard.gateway.service-token}") String serviceToken
    ) {
        if (serviceToken == null || serviceToken.length() < 32) throw new IllegalStateException("GATEWAY_SERVICE_TOKEN must contain at least 32 characters");
        this.restClient = builder.baseUrl(baseUrl).build();
        this.serviceToken = serviceToken;
    }

    public String requireExecutorDid() {
        try {
            ExecutorStatus result = restClient.get()
                .uri("/internal/executor/status")
                .header("X-Gateway-Service-Token", serviceToken)
                .header(TraceContext.HEADER, TraceContext.currentOrGenerate())
                .retrieve()
                .body(ExecutorStatus.class);
            if (result == null || !result.ready() || result.executorDid() == null || !result.executorDid().startsWith("did:t3n:")) {
                throw new GatewayUnavailableException("Protected executor is not authenticated and ready");
            }
            return result.executorDid();
        } catch (RestClientException ex) {
            throw new GatewayUnavailableException("Protected executor identity is unavailable", ex);
        }
    }

    public RemediationResult execute(RemediationRequest request, String capability) {
        if (capability == null || capability.isBlank()) throw new IllegalArgumentException("Remediation capability is required");
        if (request.approvedHost() == null || request.approvedHost().isBlank()) throw new IllegalArgumentException("Approved remediation destination is required");
        if (request.normalPayload() == null || request.normalPayload().isEmpty()) throw new IllegalArgumentException("Trusted normal remediation payload is required");
        if (request.operatorPrincipalHash() == null || !request.operatorPrincipalHash().matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Bound operator principal hash is required");
        }
        if (request.authorizationRecordedAt() <= 0) throw new IllegalArgumentException("Bound human authorization timestamp is required");
        try {
            String executorDid = requireExecutorDid();
            RemediationWireRequest wireRequest = new RemediationWireRequest(
                request.incidentId(), request.actionId(), request.decisionId(), request.requestId(), request.action(), request.resource(), request.purpose(),
                request.approvedHost(), request.fields(), request.normalPayload(), request.privateRefs(), request.policyVersion(), request.policyHash(), executorDid,
                request.operatorPrincipalHash(), request.authorizationRecordedAt()
            );
            RemediationResult result = restClient.post()
                .uri("/internal/contracts/privacy-guard/remediate")
                .header("X-Gateway-Service-Token", serviceToken)
                .header("X-Remediation-Capability", capability)
                .header(TraceContext.HEADER, TraceContext.currentOrGenerate())
                .body(wireRequest)
                .retrieve()
                .body(RemediationResult.class);
            if (result == null || !"PENDING_VERIFICATION".equals(result.status())) {
                throw new GatewayUnavailableException("Gateway returned an invalid remediation acceptance result");
            }
            if (!request.policyVersion().equals(result.policyVersion()) || !request.policyHash().equals(result.policyHash())) {
                throw new GatewayUnavailableException("Gateway remediation policy metadata does not match the approved decision");
            }
            return result;
        } catch (RestClientResponseException ex) {
            String responseBody = ex.getResponseBodyAsString();
            if (ex.getStatusCode().value() == 409 && responseBody != null && responseBody.contains("EXECUTION_DESTINATION_CHANGED")) {
                throw new RemediationDestinationChangedException("Protected destination changed after human authorization", ex);
            }
            throw new GatewayUnavailableException("Protected remediation acceptance is unavailable", ex);
        } catch (RestClientException ex) {
            throw new GatewayUnavailableException("Protected remediation acceptance is unavailable", ex);
        }
    }

    public VerificationResult verify(String requestId, String operationId) {
        if (operationId == null || operationId.isBlank()) throw new IllegalArgumentException("operationId is required for verification");
        try {
            VerificationResult result = restClient.post()
                .uri("/internal/contracts/privacy-guard/verify-remediation")
                .header("X-Gateway-Service-Token", serviceToken)
                .header(TraceContext.HEADER, TraceContext.currentOrGenerate())
                .body(new VerificationRequest(requestId, operationId, "REVOKED"))
                .retrieve()
                .body(VerificationResult.class);
            if (result == null || !("VERIFIED".equals(result.status()) || "UNVERIFIED".equals(result.status()))) {
                throw new GatewayUnavailableException("Gateway returned an invalid verification result");
            }
            return result;
        } catch (RestClientException ex) {
            throw new GatewayUnavailableException("External remediation verification is unavailable", ex);
        }
    }

    public record ExecutorStatus(boolean configured, boolean connected, boolean ready, String executorDid, String network) {}

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

    private record RemediationWireRequest(
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
        @JsonProperty("executor_did") String executorDid,
        @JsonProperty("operator_principal_hash") String operatorPrincipalHash,
        @JsonProperty("authorization_recorded_at") long authorizationRecordedAt
    ) {}

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
    }

    public record VerificationRequest(
        @JsonProperty("request_id") String requestId,
        @JsonProperty("operation_id") String operationId,
        @JsonProperty("expected_state") String expectedState
    ) {}

    public record VerificationResult(
        @JsonProperty("request_id") String requestId,
        String status,
        @JsonProperty("observed_state") String observedState,
        @JsonProperty("activity_sequence") Long activitySequence,
        @JsonProperty("activity_hash") String activityHash
    ) {
        public VerificationResult(String requestId, String status, String observedState) {
            this(requestId, status, observedState, null, null);
        }
    }
}
