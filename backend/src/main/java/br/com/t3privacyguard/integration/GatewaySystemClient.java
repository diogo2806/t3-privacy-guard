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
    private static final String SERVICE_TOKEN_HEADER = "X-Gateway-Service-Token";
    private static final int MAX_ACTIVITY_LIMIT = 200;

    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final String baseUrl;
    private final String serviceToken;

    public GatewaySystemClient(
        ObjectMapper mapper,
        @Value("${privacy-guard.gateway.base-url}") String baseUrl,
        @Value("${privacy-guard.gateway.service-token}") String serviceToken
    ) {
        this.mapper = mapper;
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.serviceToken = serviceToken;
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();
    }

    public boolean health() {
        return get("/health", HealthResponse.class, false).map(response -> "UP".equals(response.status())).orElse(false);
    }

    public Optional<TenantStatus> tenantStatus() { return get("/internal/t3n/status", TenantStatus.class, true); }
    public Optional<AgentStatus> agentStatus() { return get("/internal/agent/status", AgentStatus.class, true); }
    public Optional<ExecutorStatus> executorStatus() { return get("/internal/executor/status", ExecutorStatus.class, true); }
    public Optional<AgentRegistrationStatus> agentRegistration() { return get("/internal/agent/registration", AgentRegistrationStatus.class, true); }

    public Optional<ContractIdentity> contractIdentity() {
        return get("/internal/contracts/privacy-guard/identity", ContractIdentity.class, true)
            .filter(identity -> identity.contractVersion() != null && !identity.contractVersion().isBlank());
    }

    public Optional<DelegationStatus> delegationStatus(String contractId) {
        return delegationStatus("/internal/agent/delegations/", contractId);
    }

    public Optional<DelegationStatus> executorDelegationStatus(String contractId) {
        return delegationStatus("/internal/executor/delegations/", contractId);
    }

    private Optional<DelegationStatus> delegationStatus(String prefix, String contractId) {
        if (contractId == null || contractId.isBlank()) return Optional.empty();
        String encoded = URLEncoder.encode(contractId, StandardCharsets.UTF_8);
        return get(prefix + encoded, DelegationStatus.class, true);
    }

    public Optional<ActivityPage> activity(long fromMs, long toMs, int limit) {
        int boundedLimit = Math.max(1, Math.min(limit, MAX_ACTIVITY_LIMIT));
        String path = "/internal/t3n/activity?fromMs=" + fromMs + "&toMs=" + toMs + "&limit=" + boundedLimit;
        return get(path, ActivityPage.class, true);
    }

    private <T> Optional<T> get(String path, Class<T> type, boolean internal) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .GET()
                .timeout(Duration.ofSeconds(5))
                .header("Accept", "application/json");
            if (internal) builder.header(SERVICE_TOKEN_HEADER, serviceToken);
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
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
    public record ExecutorStatus(boolean configured, boolean connected, boolean ready, String executorDid, String network) {}
    public record AgentRegistrationStatus(String agentDid, String state, String cardUri, String cardSha256, String verifiedAt, List<String> services) {}
    public record ContractIdentity(String contractId, String contractVersion) {}
    public record DelegationStatus(String state, List<String> functions, List<String> allowedHosts) {}
    public record ActivityEvent(
        long sequence,
        String hash,
        long timestampMs,
        String callerType,
        String actorDid,
        String onBehalfOfDid,
        String contractId,
        String function,
        String outcome,
        List<String> roles
    ) {}
    public record ActivityPage(List<ActivityEvent> events, Long nextSequence, boolean complete) {
        public ActivityPage {
            events = events == null ? List.of() : List.copyOf(events);
        }
    }
}
