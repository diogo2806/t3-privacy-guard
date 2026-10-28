package br.com.t3privacyguard.integration;

import br.com.t3privacyguard.privacy.IncidentDataMinimizer;
import br.com.t3privacyguard.security.RuntimeSecretPolicy;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * The untrusted AI agent: any OpenAI-compatible chat-completions endpoint (OpenAI, Azure OpenAI, Claude's
 * compatibility layer, or a local Ollama/vLLM server). The model only sees the prompt after the sensitive-literal
 * guard, and only ever returns field names and logical private references, never values or decisions.
 */
@Component
public class AiAgentClient {
    private static final String TOOL_NAME = "propose_privacy_guard_action";
    private static final int MAX_PROMPT_LENGTH = 4_000;
    private static final Set<String> ALLOWED_KEYS = Set.of("action", "resource", "purpose", "host", "fields", "private_refs");
    private static final Set<String> FORBIDDEN_KEYS = Set.of(
        "decision", "allow", "override", "approved", "credential", "secret", "apiKey", "api_key", "agent_did", "pii_did"
    );
    private static final Set<String> KNOWN_PRIVATE_REFS = Set.of("verified_email");
    private static final Pattern LOGICAL_REFERENCE = Pattern.compile("[a-z][a-z0-9_]*");
    private static final String SYSTEM_PROMPT = "You are an incident-response agent. Propose one structured action through the provided tool. "
        + "Never decide authorization. Never invent, request or output private values. When a verified user email is operationally necessary, "
        + "request only the logical private reference verified_email; never emit a {{profile.*}} placeholder. An independent policy runtime "
        + "decides authorization and resolves private references only inside protected egress.";

    private final IncidentDataMinimizer minimizer;
    private final ObjectMapper mapper;
    private final boolean enabled;
    private final URI apiUrl;
    private final String apiKey;
    private final String model;
    private final HttpClient http;

    public AiAgentClient(
        IncidentDataMinimizer minimizer,
        ObjectMapper mapper,
        @Value("${privacy-guard.ai.provider:disabled}") String provider,
        @Value("${privacy-guard.ai.api-url:https://api.openai.com/v1/chat/completions}") String apiUrl,
        @Value("${privacy-guard.ai.api-key:}") String apiKey,
        @Value("${privacy-guard.ai.model:}") String model,
        @Value("${privacy-guard.ai.allow-insecure-http:false}") boolean allowInsecureHttp
    ) {
        this.minimizer = minimizer;
        this.mapper = mapper;
        String normalizedProvider = provider == null ? "disabled" : provider.trim().toLowerCase(Locale.ROOT);
        if (!normalizedProvider.equals("disabled") && !normalizedProvider.equals("openai-compatible")) {
            throw new IllegalStateException("AI_PROVIDER must be disabled or openai-compatible");
        }
        this.enabled = normalizedProvider.equals("openai-compatible");
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        this.model = model == null ? "" : model.trim();
        if (enabled) {
            if (this.apiKey.isEmpty() || this.model.isEmpty()) throw new IllegalStateException("AI_API_KEY and AI_MODEL are required when AI_PROVIDER=openai-compatible");
            RuntimeSecretPolicy.rejectDocumentationPlaceholder(this.apiKey, "AI_API_KEY");
            this.apiUrl = validateApiUrl(apiUrl, allowInsecureHttp);
        } else {
            this.apiUrl = null;
        }
        this.http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    }

    public boolean isEnabled() {
        return enabled;
    }

    public AgentProposalResult propose(String prompt) {
        if (!enabled) throw new AiProviderUnavailableException("AI agent provider is not configured");
        String normalized = prompt == null ? "" : prompt.trim();
        if (normalized.isEmpty() || normalized.length() > MAX_PROMPT_LENGTH) throw new IllegalArgumentException("Prompt must contain between 1 and 4000 characters");
        if (minimizer.containsSensitiveLiteral(normalized)) throw new SensitivePromptRejectedException();

        HttpResponse<byte[]> response;
        try {
            HttpRequest request = HttpRequest.newBuilder(apiUrl)
                .timeout(Duration.ofSeconds(20))
                .header("Authorization", "Bearer " + apiKey)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(mapper.writeValueAsBytes(requestBody(normalized))))
                .build();
            response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (IOException ex) {
            throw new AiProviderUnavailableException("AI agent provider is unavailable", ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new AiProviderUnavailableException("AI agent provider request was interrupted", ex);
        }
        if (response.statusCode() >= 300 && response.statusCode() < 400) throw new AiProviderUnavailableException("AI provider redirects are not allowed");
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new AiProviderUnavailableException("AI provider returned HTTP " + response.statusCode());
        }
        return new AgentProposalResult("openai-compatible", model, validateProposal(toolArguments(response.body())));
    }

    private ObjectNode requestBody(String prompt) {
        ObjectNode body = mapper.createObjectNode();
        body.put("model", model);
        body.put("temperature", 0);
        ArrayNode messages = body.putArray("messages");
        messages.addObject().put("role", "system").put("content", SYSTEM_PROMPT);
        messages.addObject().put("role", "user").put("content", prompt);

        ObjectNode function = body.putArray("tools").addObject().put("type", "function").putObject("function");
        function.put("name", TOOL_NAME);
        function.put("description", "Propose an incident-response action for independent policy evaluation. Private data is represented only by logical references.");
        ObjectNode parameters = function.putObject("parameters");
        parameters.put("type", "object");
        parameters.put("additionalProperties", false);
        parameters.putArray("required").add("action").add("resource").add("purpose").add("fields").add("private_refs");
        ObjectNode properties = parameters.putObject("properties");
        properties.putObject("action").put("type", "string");
        properties.putObject("resource").put("type", "string");
        properties.putObject("purpose").put("type", "string");
        ArrayNode hostTypes = properties.putObject("host").putArray("anyOf");
        hostTypes.addObject().put("type", "string");
        hostTypes.addObject().put("type", "null");
        ObjectNode fields = properties.putObject("fields").put("type", "array").put("maxItems", 20);
        fields.putObject("items").put("type", "string");
        ObjectNode privateRefs = properties.putObject("private_refs").put("type", "array").put("maxItems", 4)
            .put("description", "Logical private-data references only. Never include plaintext or a {{profile.*}} marker.");
        privateRefs.putObject("items").put("type", "string").putArray("enum").add("verified_email");

        body.putObject("tool_choice").put("type", "function").putObject("function").put("name", TOOL_NAME);
        return body;
    }

    private JsonNode toolArguments(byte[] payload) {
        JsonNode root;
        try {
            root = mapper.readTree(payload);
        } catch (IOException ex) {
            throw new AiProviderUnavailableException("AI provider returned a malformed response", ex);
        }
        JsonNode calls = root == null ? null : root.path("choices").path(0).path("message").path("tool_calls");
        if (calls == null || !calls.isArray() || calls.size() != 1 || !TOOL_NAME.equals(calls.get(0).path("function").path("name").asText())) {
            throw new InvalidAgentProposalException("AGENT_TOOL_CALL_REQUIRED");
        }
        String arguments = calls.get(0).path("function").path("arguments").asText("");
        if (arguments.isBlank()) throw new InvalidAgentProposalException("AGENT_TOOL_CALL_INVALID");
        try {
            return mapper.readTree(arguments);
        } catch (IOException ex) {
            throw new InvalidAgentProposalException("AGENT_TOOL_CALL_INVALID_JSON");
        }
    }

    /** Strict allowlist: anything that looks like a decision, an identity or a secret rejects the whole proposal. */
    static AgentProposal validateProposal(JsonNode value) {
        if (value == null || !value.isObject()) throw new InvalidAgentProposalException("AGENT_PROPOSAL_INVALID");
        Iterator<String> keys = value.fieldNames();
        while (keys.hasNext()) {
            String key = keys.next();
            if (FORBIDDEN_KEYS.contains(key) || !ALLOWED_KEYS.contains(key)) throw new InvalidAgentProposalException("AGENT_PROPOSAL_FORBIDDEN_FIELD");
        }
        JsonNode fieldsNode = value.get("fields");
        if (fieldsNode == null || !fieldsNode.isArray() || fieldsNode.size() > 20) throw new InvalidAgentProposalException("AGENT_PROPOSAL_INVALID_FIELDS");
        JsonNode privateRefsNode = value.has("private_refs") && !value.get("private_refs").isNull() ? value.get("private_refs") : null;
        if (privateRefsNode != null && (!privateRefsNode.isArray() || privateRefsNode.size() > 4)) {
            throw new InvalidAgentProposalException("AGENT_PROPOSAL_INVALID_PRIVATE_REFS");
        }
        List<String> fields = new ArrayList<>();
        for (JsonNode field : fieldsNode) fields.add(stringField(field, "field", 80));
        List<String> privateRefs = new ArrayList<>();
        if (privateRefsNode != null) for (JsonNode ref : privateRefsNode) privateRefs.add(privateRef(ref));
        JsonNode hostNode = value.get("host");
        String host = hostNode == null || hostNode.isNull() ? null : stringField(hostNode, "host", 253);
        return new AgentProposal(
            stringField(value.get("action"), "action", 80),
            stringField(value.get("resource"), "resource", 200),
            stringField(value.get("purpose"), "purpose", 120),
            host,
            List.copyOf(fields),
            List.copyOf(privateRefs)
        );
    }

    private static String stringField(JsonNode value, String name, int max) {
        if (value == null || !value.isTextual() || value.asText().isBlank() || value.asText().length() > max) {
            throw new InvalidAgentProposalException("AGENT_PROPOSAL_INVALID_" + name.toUpperCase(Locale.ROOT));
        }
        return value.asText().trim();
    }

    private static String privateRef(JsonNode value) {
        String ref = stringField(value, "private_ref", 64).toLowerCase(Locale.ROOT);
        if (ref.contains("{{") || ref.contains("}}") || ref.startsWith("profile.") || !LOGICAL_REFERENCE.matcher(ref).matches()) {
            throw new InvalidAgentProposalException("AGENT_PROPOSAL_RAW_PLACEHOLDER_FORBIDDEN");
        }
        if (!KNOWN_PRIVATE_REFS.contains(ref)) throw new InvalidAgentProposalException("AGENT_PROPOSAL_PRIVATE_REFERENCE_UNKNOWN");
        return ref;
    }

    /** https for remote providers; plain http only on loopback unless AI_ALLOW_INSECURE_HTTP is set for an internal model server. */
    static URI validateApiUrl(String value, boolean allowInsecureHttp) {
        URI uri;
        try {
            uri = URI.create(value == null ? "" : value.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalStateException("AI_API_URL must be a valid URL");
        }
        if (uri.getHost() == null || uri.getUserInfo() != null) throw new IllegalStateException("AI_API_URL must be an absolute URL without embedded credentials");
        if ("https".equals(uri.getScheme())) return uri;
        if (!"http".equals(uri.getScheme())) throw new IllegalStateException("AI_API_URL must use https or http");
        String host = uri.getHost().toLowerCase(Locale.ROOT);
        boolean loopback = host.equals("localhost") || host.equals("[::1]") || host.equals("::1") || host.startsWith("127.");
        if (!loopback && !allowInsecureHttp) {
            throw new IllegalStateException("AI_API_URL must use https for remote providers; http is allowed on loopback or with AI_ALLOW_INSECURE_HTTP=true");
        }
        return uri;
    }

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
