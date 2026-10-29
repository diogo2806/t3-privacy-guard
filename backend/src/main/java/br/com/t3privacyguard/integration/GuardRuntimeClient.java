package br.com.t3privacyguard.integration;

import br.com.t3privacyguard.observability.TraceContext;
import br.com.t3privacyguard.security.RuntimeSecretPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * HTTP access to guard-runtime. The backend holds separate runtime credentials, exactly as the trust model requires:
 * the proposal agent may only evaluate, the protected executor may only execute and verify, and the optional policy
 * administrator may only manage policy versions. No token ever appears in an exception message or log.
 */
@Component
public class GuardRuntimeClient {
    public enum Caller { PROPOSAL, EXECUTOR, POLICY_ADMIN }

    /** activitySequence/activityHash come from the runtime's X-Activity-* headers when the call was logged. */
    public record Response(int status, JsonNode body, Long activitySequence, String activityHash) {
        public boolean ok() {
            return status >= 200 && status < 300;
        }
    }

    private static final Pattern CALLER_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final Pattern ACTIVITY_HASH = Pattern.compile("[0-9a-f]{64}");
    /** Docker Swarm / EasyPanel internal names look like project_service, which java.net.URI does not accept as a host. */
    private static final Pattern UNDERSCORE_HTTP_URL = Pattern.compile("http://([A-Za-z0-9][A-Za-z0-9_.-]*):([0-9]{1,5})(/[A-Za-z0-9._~/-]*)?");
    private static final int MIN_TOKEN_LENGTH = 32;
    private static final int MAX_TOKEN_LENGTH = 512;

    private final ObjectMapper mapper;
    private final HttpClient http;
    private final String baseUrl;
    /** Set when the configured host has an underscore: requests go to its resolved address instead. */
    private final String underscoreHost;
    private HostResolver resolver = InetAddress::getByName;
    private final String proposalAgentId;
    private final String proposalToken;
    private final String executorId;
    private final String executorToken;
    private final String policyAdminToken;
    private final Duration timeout;

    public GuardRuntimeClient(
        ObjectMapper mapper,
        String url,
        String proposalAgentId,
        String proposalToken,
        String executorId,
        String executorToken,
        long timeoutMs
    ) {
        this(mapper, url, proposalAgentId, proposalToken, executorId, executorToken, "", timeoutMs);
    }

    @Autowired
    public GuardRuntimeClient(
        ObjectMapper mapper,
        @Value("${privacy-guard.guard-runtime.url:}") String url,
        @Value("${privacy-guard.guard-runtime.proposal-agent-id:agent:proposal}") String proposalAgentId,
        @Value("${privacy-guard.guard-runtime.proposal-token:}") String proposalToken,
        @Value("${privacy-guard.guard-runtime.executor-id:agent:executor}") String executorId,
        @Value("${privacy-guard.guard-runtime.executor-token:}") String executorToken,
        @Value("${privacy-guard.guard-runtime.policy-admin-token:}") String policyAdminToken,
        @Value("${privacy-guard.guard-runtime.timeout-ms:15000}") long timeoutMs
    ) {
        this.mapper = mapper;
        this.baseUrl = requireUrl(url);
        this.underscoreHost = underscoreHost(this.baseUrl);
        this.proposalAgentId = requireCallerId(proposalAgentId, "GUARD_RUNTIME_PROPOSAL_AGENT_ID");
        this.executorId = requireCallerId(executorId, "GUARD_RUNTIME_EXECUTOR_ID");
        this.proposalToken = requireToken(proposalToken, "GUARD_RUNTIME_PROPOSAL_TOKEN");
        this.executorToken = requireToken(executorToken, "GUARD_RUNTIME_EXECUTOR_TOKEN");
        if (this.proposalAgentId.equals(this.executorId)) {
            throw new IllegalStateException("GUARD_RUNTIME_PROPOSAL_AGENT_ID and GUARD_RUNTIME_EXECUTOR_ID must be different");
        }
        if (this.proposalToken.equals(this.executorToken)) {
            throw new IllegalStateException("GUARD_RUNTIME_PROPOSAL_TOKEN and GUARD_RUNTIME_EXECUTOR_TOKEN must be different");
        }
        // Optional: without it the dashboard shows the policy as read-only.
        this.policyAdminToken = policyAdminToken == null || policyAdminToken.isBlank()
            ? null
            : requireToken(policyAdminToken, "GUARD_RUNTIME_POLICY_ADMIN_TOKEN");
        if (this.policyAdminToken != null && (this.policyAdminToken.equals(this.proposalToken) || this.policyAdminToken.equals(this.executorToken))) {
            throw new IllegalStateException("GUARD_RUNTIME_POLICY_ADMIN_TOKEN must differ from the proposal and executor tokens");
        }
        if (timeoutMs < 100 || timeoutMs > 60_000) throw new IllegalStateException("GUARD_RUNTIME_TIMEOUT_MS must be between 100 and 60000");
        this.timeout = Duration.ofMillis(timeoutMs);
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    }

    public String proposalAgentId() {
        return proposalAgentId;
    }

    public String executorId() {
        return executorId;
    }

    public boolean policyAdministrationConfigured() {
        return policyAdminToken != null;
    }

    /** All runtime tokens, so other secrets can be checked for accidental reuse. */
    public boolean usesToken(String candidate) {
        return candidate != null && (candidate.equals(proposalToken) || candidate.equals(executorToken) || candidate.equals(policyAdminToken));
    }

    public Response post(String path, Caller caller, Object body) {
        try {
            HttpRequest request = authorized(path, caller)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(body)))
                .build();
            return send(request);
        } catch (IOException ex) {
            throw new TrustRuntimeUnavailableException("guard-runtime request could not be encoded", ex);
        }
    }

    public Response get(String path, Caller caller) {
        return send(authorized(path, caller).GET().build());
    }

    /** Unauthenticated endpoints such as the health probe. */
    public Response getPublic(String path) {
        return send(HttpRequest.newBuilder(target(path)).timeout(timeout).header("Accept", "application/json").GET().build());
    }

    private HttpRequest.Builder authorized(String path, Caller caller) {
        String token = switch (caller) {
            case PROPOSAL -> proposalToken;
            case EXECUTOR -> executorToken;
            case POLICY_ADMIN -> policyAdminToken;
        };
        if (token == null) throw new IllegalStateException("GUARD_RUNTIME_POLICY_ADMIN_TOKEN is not configured");
        return HttpRequest.newBuilder(target(path))
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("Authorization", "Bearer " + token)
            .header(TraceContext.HEADER, TraceContext.currentOrGenerate());
    }

    /**
     * guard-runtime does not check the Host header, so an internal name java.net.URI rejects is reached through the
     * address it resolves to, looked up on every call because container addresses change on redeploy.
     */
    private URI target(String path) {
        if (underscoreHost == null) return URI.create(baseUrl + path);
        try {
            InetAddress address = resolver.resolve(underscoreHost);
            String literal = address instanceof Inet6Address ? "[" + address.getHostAddress() + "]" : address.getHostAddress();
            return URI.create(baseUrl.replaceFirst("^http://" + Pattern.quote(underscoreHost), "http://" + literal) + path);
        } catch (UnknownHostException ex) {
            throw new TrustRuntimeUnavailableException("guard-runtime host could not be resolved", ex);
        }
    }

    /** Tests only: answers the lookup of an underscore host. */
    void resolver(HostResolver resolver) {
        this.resolver = resolver;
    }

    interface HostResolver {
        InetAddress resolve(String host) throws UnknownHostException;
    }

    private Response send(HttpRequest request) {
        try {
            HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
            JsonNode body = response.body() == null || response.body().length == 0 ? null : parse(response.body());
            String sequence = response.headers().firstValue("X-Activity-Sequence").orElse(null);
            String hash = response.headers().firstValue("X-Activity-Hash").orElse(null);
            Long activitySequence = sequence != null && sequence.matches("[1-9][0-9]{0,17}") ? Long.valueOf(sequence) : null;
            String activityHash = hash != null && ACTIVITY_HASH.matcher(hash).matches() ? hash : null;
            return new Response(response.statusCode(), body, activitySequence, activitySequence == null ? null : activityHash);
        } catch (IOException ex) {
            throw new TrustRuntimeUnavailableException("guard-runtime is unreachable", ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new TrustRuntimeUnavailableException("guard-runtime request was interrupted", ex);
        }
    }

    private JsonNode parse(byte[] body) {
        try {
            return mapper.readTree(body);
        } catch (IOException ex) {
            return null;
        }
    }

    private static String requireUrl(String value) {
        String url = value == null ? "" : value.trim().replaceAll("/+$", "");
        if (UNDERSCORE_HTTP_URL.matcher(url).matches() && url.substring(7).split("[:/]")[0].contains("_")) return url;
        URI parsed;
        try {
            parsed = URI.create(url);
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("GUARD_RUNTIME_URL must be a valid absolute URL");
        }
        if (url.isEmpty() || parsed.getHost() == null || !("http".equals(parsed.getScheme()) || "https".equals(parsed.getScheme()))
            || parsed.getUserInfo() != null || parsed.getQuery() != null || parsed.getFragment() != null) {
            throw new IllegalStateException("GUARD_RUNTIME_URL must be an http(s) URL without credentials, query or fragment"
                + " (an internal name with an underscore needs http:// and an explicit port)");
        }
        return url;
    }

    private static String underscoreHost(String url) {
        if (!url.startsWith("http://")) return null;
        String host = url.substring(7).split("[:/]")[0];
        return host.contains("_") ? host : null;
    }

    private static String requireCallerId(String value, String name) {
        String id = value == null ? "" : value.trim();
        if (!CALLER_ID.matcher(id).matches()) throw new IllegalStateException(name + " must be a caller id configured in guard-runtime");
        return id;
    }

    private static String requireToken(String value, String name) {
        String token = value == null ? "" : value.trim();
        if (token.length() < MIN_TOKEN_LENGTH || token.length() > MAX_TOKEN_LENGTH) {
            throw new IllegalStateException(name + " must contain between 32 and 512 characters");
        }
        RuntimeSecretPolicy.rejectDocumentationPlaceholder(token, name);
        return token;
    }
}
