package br.com.t3privacyguard.integration;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class GatewayRemediationClient {
    private final RestClient restClient;
    private final String serviceToken;

    public GatewayRemediationClient(
        RestClient.Builder builder,
        @Value("${privacy-guard.gateway.base-url}") String baseUrl,
        @Value("${privacy-guard.gateway.service-token}") String serviceToken
    ) {
        if (serviceToken == null || serviceToken.length() < 32) {
            throw new IllegalStateException("GATEWAY_SERVICE_TOKEN must contain at least 32 characters");
        }
        this.restClient = builder.baseUrl(baseUrl).build();
        this.serviceToken = serviceToken;
    }

    public RemediationResult execute(RemediationRequest request, String capability) {
        if (capability == null || capability.isBlank()) {
            throw new IllegalArgumentException("Remediation capability is required");
        }
        try {
            RemediationResult result = restClient.post()
                .uri("/internal/contracts/privacy-guard/remediate")
                .header("X-Gateway-Service-Token", serviceToken)
                .header("X-Remediation-Capability", capability)
                .body(request)
                .retrieve()
                .body(RemediationResult.class);

            if (result == null || !"COMPLETED".equals(result.status())) {
                throw new GatewayUnavailableException("Gateway returned an invalid remediation result");
            }
            return result;
        } catch (RestClientException ex) {
            throw new GatewayUnavailableException("Protected remediation is unavailable", ex);
        }
    }

    public record RemediationRequest(
        @JsonProperty("incident_id") String incidentId,
        @JsonProperty("action_id") String actionId,
        @JsonProperty("decision_id") String decisionId,
        @JsonProperty("request_id") String requestId,
        String action,
        String resource,
        String purpose,
        List<String> fields
    ) {}

    public record RemediationResult(
        @JsonProperty("request_id") String requestId,
        String status,
        @JsonProperty("http_code") int httpCode,
        @JsonProperty("operation_id") String operationId
    ) {}
}
