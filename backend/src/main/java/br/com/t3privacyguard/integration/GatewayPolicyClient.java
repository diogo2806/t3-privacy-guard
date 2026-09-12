package br.com.t3privacyguard.integration;

import br.com.t3privacyguard.domain.DecisionType;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

@Component
public class GatewayPolicyClient {
    private final RestClient restClient;

    public GatewayPolicyClient(RestClient.Builder builder, @Value("${privacy-guard.gateway.base-url}") String baseUrl) {
        this.restClient = builder.baseUrl(baseUrl).build();
    }

    public GatewayDecision evaluate(GatewayEvaluationRequest request) {
        try {
            GatewayDecision decision = restClient.post()
                .uri("/internal/contracts/privacy-guard/evaluate")
                .body(request)
                .retrieve()
                .body(GatewayDecision.class);
            if (decision == null) throw new GatewayUnavailableException("Gateway returned an empty policy decision");
            return decision;
        } catch (RestClientException ex) {
            throw new GatewayUnavailableException("T3N policy evaluation is unavailable", ex);
        }
    }

    public record GatewayEvaluationRequest(
        @JsonProperty("request_id") String requestId,
        String action,
        String resource,
        String purpose,
        String host,
        List<String> fields,
        @JsonProperty("private_refs") List<String> privateRefs
    ) {}

    public record GatewayDecision(
        @JsonProperty("request_id") String requestId,
        DecisionType decision,
        @JsonProperty("reason_code") String reasonCode,
        String reason,
        @JsonProperty("allowed_fields") List<String> allowedFields,
        @JsonProperty("redacted_fields") List<String> redactedFields,
        @JsonProperty("allowed_private_refs") List<String> allowedPrivateRefs,
        @JsonProperty("redacted_private_refs") List<String> redactedPrivateRefs,
        @JsonProperty("policy_version") String policyVersion,
        @JsonProperty("policy_hash") String policyHash,
        @JsonProperty("requires_human_authorization") Boolean requiresHumanAuthorization
    ) {}
}
