package br.com.t3privacyguard.integration;

import br.com.t3privacyguard.integration.GuardRuntimeClient.Caller;
import br.com.t3privacyguard.integration.GuardRuntimeClient.Response;
import br.com.t3privacyguard.integration.PolicyAdministrationException.Kind;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Policy administration through guard-runtime's /v1/policy with the policy-admin caller. guard-runtime validates and
 * stores every version; the backend only relays the operator's request and names the human who made it.
 */
@Component
public class RuntimePolicyAdminClient {
    private static final Pattern REQUESTED_BY_UNSAFE = Pattern.compile("[^A-Za-z0-9._:@-]");
    private static final Pattern HASH = Pattern.compile("[a-f0-9]{64}");
    private static final Pattern VERSION = Pattern.compile("[A-Za-z0-9._:-]{1,64}");

    private final GuardRuntimeClient runtime;

    public RuntimePolicyAdminClient(GuardRuntimeClient runtime) {
        this.runtime = runtime;
    }

    public boolean configured() {
        return runtime.policyAdministrationConfigured();
    }

    public PolicyView current() {
        if (!configured()) return PolicyView.notConfigured();
        JsonNode body = require(runtime.get("/v1/policy", Caller.POLICY_ADMIN));
        return new PolicyView(
            true,
            body.path("managed").asBoolean(false),
            text(body, "state"),
            text(body, "version"),
            text(body, "hash"),
            body.path("document").isObject() ? body.get("document") : null,
            text(body, "reason")
        );
    }

    public List<PolicyHistoryEntry> history(int limit) {
        requireConfigured();
        JsonNode body = require(runtime.get("/v1/policy/history?limit=" + limit, Caller.POLICY_ADMIN));
        List<PolicyHistoryEntry> entries = new ArrayList<>();
        for (JsonNode entry : body.path("entries")) {
            entries.add(new PolicyHistoryEntry(
                entry.path("sequence").asLong(),
                text(entry, "operation"),
                text(entry, "version"),
                text(entry, "hash"),
                text(entry, "previous_version"),
                text(entry, "previous_hash"),
                text(entry, "caller"),
                text(entry, "requested_by"),
                text(entry, "timestamp")
            ));
        }
        return List.copyOf(entries);
    }

    public PolicyVersion version(String version) {
        requireConfigured();
        if (version == null || !VERSION.matcher(version).matches()) {
            throw new PolicyAdministrationException(Kind.NOT_FOUND, "VERSION_NOT_FOUND", "That policy version was never published.");
        }
        JsonNode body = require(runtime.get("/v1/policy/versions/" + URLEncoder.encode(version, StandardCharsets.UTF_8), Caller.POLICY_ADMIN));
        return new PolicyVersion(text(body, "version"), text(body, "hash"), body.get("document"));
    }

    public PolicyValidation validate(JsonNode document) {
        requireConfigured();
        JsonNode body = require(runtime.post("/v1/policy/validate", Caller.POLICY_ADMIN, Map.of("document", document)));
        boolean valid = body.path("valid").asBoolean(false);
        return new PolicyValidation(valid, text(body, "reason"), text(body, "version"), text(body, "hash"), valid ? body.get("document") : null);
    }

    public PolicyChange publish(JsonNode document, String expectedCurrentHash, String requestedBy) {
        requireConfigured();
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("document", document);
        request.put("expected_current_hash", expectedHash(expectedCurrentHash));
        request.put("requested_by", requestedBy(requestedBy));
        return change(runtime.post("/v1/policy/publish", Caller.POLICY_ADMIN, request));
    }

    public PolicyChange rollback(String version, String expectedCurrentHash, String requestedBy) {
        requireConfigured();
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("version", version);
        request.put("expected_current_hash", expectedHash(expectedCurrentHash));
        request.put("requested_by", requestedBy(requestedBy));
        return change(runtime.post("/v1/policy/rollback", Caller.POLICY_ADMIN, request));
    }

    private PolicyChange change(Response response) {
        JsonNode body = require(response);
        return new PolicyChange(
            body.path("changed").asBoolean(false),
            text(body, "version"),
            text(body, "hash"),
            text(body, "previous_version"),
            text(body, "previous_hash")
        );
    }

    private void requireConfigured() {
        if (!configured()) {
            throw new PolicyAdministrationException(Kind.UNAVAILABLE, "POLICY_ADMIN_NOT_CONFIGURED",
                "Policy administration is not configured: set GUARD_RUNTIME_POLICY_ADMIN_TOKEN for a guard-runtime caller granted manage-policy.");
        }
    }

    /** Maps guard-runtime's answer to a result or a typed refusal; the runtime's own reason text is a fixed rule message. */
    private static JsonNode require(Response response) {
        JsonNode body = response.body();
        String error = body == null ? null : text(body, "error");
        if (response.ok() && body != null) return body;
        if (response.status() == 401 || response.status() == 403) {
            throw new PolicyAdministrationException(Kind.UNAVAILABLE, "POLICY_ADMIN_NOT_GRANTED",
                "guard-runtime does not grant manage-policy to the configured policy administration credential.");
        }
        if (response.status() == 409 && "POLICY_MANAGEMENT_DISABLED".equals(error)) {
            throw new PolicyAdministrationException(Kind.UNAVAILABLE, error,
                "guard-runtime keeps policy as a read-only file: set GUARD_RUNTIME_POLICY_DIR to publish versions.");
        }
        if (response.status() == 409 && "POLICY_CHANGED".equals(error)) {
            throw new PolicyAdministrationException(Kind.CONFLICT, error, "The policy changed since you opened it. Reload and apply your changes again.");
        }
        if (response.status() == 409 && "VERSION_EXISTS".equals(error)) {
            throw new PolicyAdministrationException(Kind.CONFLICT, error, "That version was already published. Choose a new version name or roll back to it.");
        }
        if (response.status() == 404) {
            throw new PolicyAdministrationException(Kind.NOT_FOUND, "VERSION_NOT_FOUND", "That policy version was never published.");
        }
        if (response.status() == 422 && "POLICY_INVALID".equals(error)) {
            throw new PolicyAdministrationException(Kind.INVALID, error, safeReason(text(body, "reason")));
        }
        if (response.status() == 400) {
            throw new PolicyAdministrationException(Kind.INVALID, "INVALID_INPUT", "guard-runtime rejected the request as malformed.");
        }
        throw new TrustRuntimeUnavailableException("guard-runtime policy administration failed with HTTP " + response.status());
    }

    private static String safeReason(String reason) {
        if (reason == null || !reason.startsWith("policy ") || reason.length() > 200) return "The policy document is invalid.";
        return reason;
    }

    private static String expectedHash(String value) {
        if (value == null || value.isBlank()) return null;
        if (!HASH.matcher(value).matches()) {
            throw new PolicyAdministrationException(Kind.CONFLICT, "POLICY_CHANGED", "The policy changed since you opened it. Reload and apply your changes again.");
        }
        return value;
    }

    /** guard-runtime accepts 1-128 characters of [A-Za-z0-9._:@-]; anything else in a username becomes "_". */
    static String requestedBy(String principal) {
        if (principal == null || principal.isBlank()) return null;
        String safe = REQUESTED_BY_UNSAFE.matcher(principal.trim()).replaceAll("_");
        if (!Character.isLetterOrDigit(safe.charAt(0))) safe = "u" + safe;
        return safe.length() > 128 ? safe.substring(0, 128) : safe;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    public record PolicyView(
        boolean administrationConfigured,
        boolean managed,
        String state,
        String version,
        String hash,
        JsonNode document,
        String reason
    ) {
        static PolicyView notConfigured() {
            return new PolicyView(false, false, "UNKNOWN", null, null, null, null);
        }
    }

    public record PolicyHistoryEntry(
        long sequence,
        String operation,
        String version,
        String hash,
        String previousVersion,
        String previousHash,
        String caller,
        String requestedBy,
        String timestamp
    ) {}

    public record PolicyVersion(String version, String hash, JsonNode document) {}

    public record PolicyValidation(boolean valid, String reason, String version, String hash, JsonNode document) {}

    public record PolicyChange(boolean changed, String version, String hash, String previousVersion, String previousHash) {}
}
