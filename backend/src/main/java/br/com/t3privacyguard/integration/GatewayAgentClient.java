package br.com.t3privacyguard.integration;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;

@Component
public class GatewayAgentClient {
    private final RestClient restClient;
    private final String serviceToken;

    public GatewayAgentClient(
        RestClient.Builder builder,
        @Value("${privacy-guard.gateway.base-url}") String baseUrl,
        @Value("${privacy-guard.gateway.service-token}") String serviceToken
    ) {
        this.restClient = builder.baseUrl(baseUrl).build();
        this.serviceToken = serviceToken;
    }

    public AgentProposalResult propose(String prompt) {
        try {
            AgentProposalResult result = restClient.post()
                .uri("/internal/ai-agent/propose")
                .header("X-Gateway-Service-Token", serviceToken)
                .body(new AgentPromptRequest(prompt))
                .retrieve()
                .body(AgentProposalResult.class);
            if (result == null || result.proposal() == null || result.provider() == null || result.model() == null) {
                throw new GatewayUnavailableException("AI agent returned an invalid structured proposal");
            }
            return result;
        } catch (RestClientResponseException ex) {
            if (ex.getStatusCode().value() == HttpStatus.UNPROCESSABLE_ENTITY.value()) {
                throw new SensitivePromptRejectedException();
            }
            throw new GatewayUnavailableException("AI agent provider is unavailable", ex);
        } catch (RestClientException ex) {
            throw new GatewayUnavailableException("AI agent provider is unavailable", ex);
        }
    }

    public record AgentPromptRequest(String prompt) {}
    public record AgentProposalResult(String provider, String model, AgentProposal proposal) {}
    public record AgentProposal(
        String action,
        String resource,
        String purpose,
        String host,
        List<String> fields,
        @JsonProperty("private_refs") List<String> privateRefs
    ) {}
}
