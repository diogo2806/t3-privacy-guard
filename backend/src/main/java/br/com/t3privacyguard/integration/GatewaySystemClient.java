package br.com.t3privacyguard.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class GatewaySystemClient {
    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final String baseUrl;

    public GatewaySystemClient(ObjectMapper mapper, @Value("${privacy-guard.gateway.base-url}") String baseUrl) {
        this.mapper = mapper;
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    }

    public boolean health() {
        return get("/health", HealthResponse.class).map(response -> "UP".equals(response.status())).orElse(false);
    }

    public Optional<TenantStatus> tenantStatus() { return get("/internal/t3n/status", TenantStatus.class); }
    public Optional<AgentStatus> agentStatus() { return get("/internal/agent/status", AgentStatus.class); }

    public Optional<ContractIdentity> contractIdentity() {
        return get("/internal/contracts/privacy-guard/identity", ContractIdentity.class)
            .filter(identity -> identity.contractVersion() != null && !identity.contractVersion().isBlank());
    }

    public Optional<DelegationStatus> delegationStatus(String contractId) {
        if (contractId == null || contractId.isBlank()) return Optional.empty();
        String encoded = URLEncoder.encode(contractId, StandardCharsets.UTF_8);
        return get("/internal/agent/delegations/" + encoded, DelegationStatus.class);
    }

    private <T> Optional<T> get(String path, Class<T> type) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .GET().timeout(Duration.ofSeconds(5)).header("Accept", "application/json").build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300 || response.body() == null || response.body().isBlank()) return Optional.empty();
            return Optional.of(mapper.readValue(response.body(), type));
        } catch (IOException | InterruptedException | RuntimeException ex) {
            if (ex instanceof InterruptedException) Thread.currentThread().interrupt();
            return Optional.empty();
        }
    }

    public record HealthResponse(String status, String service) {}
    public record TenantStatus(boolean connected, boolean ready, String tenantDid, String network) {}
    public record AgentStatus(boolean configured, boolean connected, boolean ready, String agentDid, String network) {}
    public record ContractIdentity(String contractId, String contractVersion) {}
    public record DelegationStatus(String state, List<String> functions, List<String> allowedHosts) {}
}
