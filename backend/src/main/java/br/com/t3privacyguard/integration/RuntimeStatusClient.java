package br.com.t3privacyguard.integration;

import br.com.t3privacyguard.integration.GuardRuntimeClient.Caller;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Control-plane status read from guard-runtime: runtime identity, the two callers' authentication and effective
 * function grants, external-integration readiness and the activity log used for audit provenance. Every read fails
 * soft (empty or UNKNOWN) so the dashboard shows "not confirmed" instead of an error.
 */
@Component
public class RuntimeStatusClient {
    public static final String NETWORK = "selfhosted";
    private static final int MAX_ACTIVITY_LIMIT = 200;
    private static final List<String> PROPOSAL_FUNCTIONS = List.of("evaluate-action");
    private static final List<String> EXECUTOR_FUNCTIONS = List.of("execute-remediation", "verify-remediation");
    private static final List<String> MEMBER_DELEGATION_STATES = List.of("ACTIVE", "SCHEDULED", "REVOKED", "NOT_GRANTED", "UNKNOWN");
    private static final List<String> EFFECTIVE_DELEGATION_STATES = List.of("ACTIVE", "DENIED", "UNKNOWN");
    private static final List<String> ENTERPRISE_INTEGRATION_STATES = List.of("READY", "INCOMPLETE", "MISMATCH", "UNKNOWN");
    private static final List<String> ENTERPRISE_INTEGRATION_DIAGNOSTIC_CODES = List.of(
        "NONE",
        "POLICY_UNAVAILABLE",
        "POLICY_INVALID",
        "PRIVATE_CONFIGURATION_UNAVAILABLE",
        "ENDPOINT_CONFIGURATION_INVALID",
        "DELEGATION_UNAVAILABLE",
        "TRUST_RUNTIME_UNAVAILABLE"
    );

    private final GuardRuntimeClient runtime;
    private final ObjectMapper mapper;

    public RuntimeStatusClient(GuardRuntimeClient runtime, ObjectMapper mapper) {
        this.runtime = runtime;
        this.mapper = mapper;
    }

    public boolean health() {
        try {
            GuardRuntimeClient.Response response = runtime.getPublic("/actuator/health");
            return response.ok() && response.body() != null && "UP".equals(response.body().path("status").asText());
        } catch (TrustRuntimeUnavailableException ex) {
            return false;
        }
    }

    public Optional<TenantStatus> tenantStatus() {
        return readiness().map(readiness -> new TenantStatus(true, true, readiness.path("tenant_id").asText(null), NETWORK));
    }

    public Optional<AgentStatus> agentStatus() {
        return caller(Caller.PROPOSAL).map(caller -> {
            boolean ready = runtime.proposalAgentId().equals(caller.id());
            return new AgentStatus(true, true, ready, ready ? caller.id() : null, NETWORK);
        });
    }

    public Optional<ExecutorStatus> executorStatus() {
        return caller(Caller.EXECUTOR).map(caller -> {
            boolean ready = runtime.executorId().equals(caller.id());
            return new ExecutorStatus(true, true, ready, ready ? caller.id() : null, NETWORK);
        });
    }

    public Optional<ContractIdentity> contractIdentity() {
        return readiness()
            .map(readiness -> new ContractIdentity(readiness.path("contract_id").asText(null), readiness.path("contract_version").asText(null)))
            .filter(identity -> identity.contractId() != null && identity.contractVersion() != null && !identity.contractVersion().isBlank());
    }

    public Optional<DelegationStatus> delegationStatus(String contractId) {
        return Optional.of(delegation(Caller.PROPOSAL, PROPOSAL_FUNCTIONS, null));
    }

    public Optional<DelegationStatus> executorDelegationStatus(String contractId) {
        return Optional.of(delegation(Caller.EXECUTOR, EXECUTOR_FUNCTIONS, readiness().orElse(null)));
    }

    public Optional<EnterpriseIntegrationReadiness> enterpriseIntegrationReadiness() {
        String checkedAt = Instant.now().toString();
        Optional<JsonNode> loaded = readiness();
        if (loaded.isEmpty()) return Optional.of(EnterpriseIntegrationRules.unknown(checkedAt, "TRUST_RUNTIME_UNAVAILABLE"));
        JsonNode readiness = loaded.get();
        String policyState = readiness.path("policy_state").asText();
        JsonNode actions = readiness.path("policy_document").path("actions");
        if ("UNAVAILABLE".equals(policyState)) return Optional.of(EnterpriseIntegrationRules.unknown(checkedAt, "POLICY_UNAVAILABLE"));
        if (!"AVAILABLE".equals(policyState) || !actions.isObject()) return Optional.of(EnterpriseIntegrationRules.unknown(checkedAt, "POLICY_INVALID"));
        if (!readiness.path("endpoint_configuration_valid").asBoolean(false)) {
            return Optional.of(EnterpriseIntegrationRules.unknown(checkedAt, "ENDPOINT_CONFIGURATION_INVALID"));
        }
        // Without a capability verification key nothing can execute, so it counts as missing credentials.
        boolean credentialConfigured = readiness.path("credential_configured").asBoolean(false)
            && readiness.path("verification_key_configured").asBoolean(false);
        return Optional.of(EnterpriseIntegrationRules.evaluate(
            textOrNull(readiness, "execution_host"),
            textOrNull(readiness, "verification_host"),
            credentialConfigured,
            actions,
            delegation(Caller.EXECUTOR, EXECUTOR_FUNCTIONS, readiness),
            checkedAt
        ));
    }

    public Optional<ActivityPage> activity(long fromMs, long toMs, int limit) {
        int boundedLimit = Math.max(1, Math.min(limit, MAX_ACTIVITY_LIMIT));
        try {
            GuardRuntimeClient.Response response = runtime.get(
                "/v1/activity?fromMs=" + fromMs + "&toMs=" + toMs + "&limit=" + boundedLimit, Caller.PROPOSAL);
            if (!response.ok() || response.body() == null) return Optional.empty();
            return Optional.of(mapper.treeToValue(response.body(), ActivityPage.class));
        } catch (TrustRuntimeUnavailableException | JsonProcessingException | IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    /** Member grant = guard-runtime knows the caller; effective access = it holds every function the role needs. */
    private DelegationStatus delegation(Caller kind, List<String> required, JsonNode readiness) {
        String expectedId = kind == Caller.PROPOSAL ? runtime.proposalAgentId() : runtime.executorId();
        GuardRuntimeClient.Response response;
        try {
            response = runtime.get("/v1/caller", kind);
        } catch (TrustRuntimeUnavailableException ex) {
            return new DelegationStatus("UNKNOWN", "UNKNOWN", List.of(), List.of(), List.of(), required, List.of());
        }
        if (response.status() == 401) return new DelegationStatus("NOT_GRANTED", "DENIED", List.of(), List.of(), List.of(), required, List.of());
        if (!response.ok() || response.body() == null) {
            return new DelegationStatus("UNKNOWN", "UNKNOWN", List.of(), List.of(), List.of(), required, List.of());
        }
        List<String> functions = texts(response.body().path("functions"));
        if (!expectedId.equals(response.body().path("id").asText(null))) {
            return new DelegationStatus("NOT_GRANTED", "DENIED", functions, List.of(), List.of(), required, List.of());
        }
        String effective = functions.containsAll(required) ? "ACTIVE" : "DENIED";
        List<String> allowedHosts = kind == Caller.EXECUTOR && readiness != null
            ? EnterpriseIntegrationRules.remediationHosts(readiness.path("policy_document").path("actions"))
            : List.of();
        return new DelegationStatus("ACTIVE", effective, functions, List.of(), allowedHosts, required, List.of());
    }

    private Optional<JsonNode> readiness() {
        try {
            GuardRuntimeClient.Response response = runtime.get("/v1/readiness", Caller.EXECUTOR);
            return response.ok() && response.body() != null ? Optional.of(response.body()) : Optional.empty();
        } catch (TrustRuntimeUnavailableException ex) {
            return Optional.empty();
        }
    }

    private Optional<RuntimeCaller> caller(Caller kind) {
        try {
            GuardRuntimeClient.Response response = runtime.get("/v1/caller", kind);
            if (!response.ok() || response.body() == null) return Optional.empty();
            return Optional.of(new RuntimeCaller(response.body().path("id").asText(null), texts(response.body().path("functions"))));
        } catch (TrustRuntimeUnavailableException ex) {
            return Optional.empty();
        }
    }

    private static List<String> texts(JsonNode array) {
        List<String> result = new ArrayList<>();
        if (array != null && array.isArray()) for (JsonNode item : array) if (item.isTextual()) result.add(item.asText());
        return List.copyOf(result);
    }

    private static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }

    private static List<String> safeList(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private static String safeHostname(String value) {
        if (value == null) return null;
        String normalized = value.trim().toLowerCase();
        if (normalized.isBlank() || normalized.length() > 253 || normalized.matches(".*[\\s/:@].*")) return null;
        return normalized;
    }

    private record RuntimeCaller(String id, List<String> functions) {}

    public record TenantStatus(boolean connected, boolean ready, String tenantDid, String network) {}
    public record AgentStatus(boolean configured, boolean connected, boolean ready, String agentDid, String network) {}
    public record ExecutorStatus(boolean configured, boolean connected, boolean ready, String executorDid, String network) {}
    public record ContractIdentity(String contractId, String contractVersion) {}
    public record DelegationStatus(
        String memberState,
        String effectiveState,
        List<String> functions,
        List<String> scopes,
        List<String> allowedHosts,
        List<String> checkedFunctions,
        List<String> checkedScopes
    ) {
        public DelegationStatus {
            memberState = MEMBER_DELEGATION_STATES.contains(memberState) ? memberState : "UNKNOWN";
            effectiveState = EFFECTIVE_DELEGATION_STATES.contains(effectiveState) ? effectiveState : "UNKNOWN";
            functions = safeList(functions);
            scopes = safeList(scopes);
            allowedHosts = safeList(allowedHosts);
            checkedFunctions = safeList(checkedFunctions);
            checkedScopes = safeList(checkedScopes);
        }
    }
    public record EnterpriseVerificationContract(String action, String expectedState) {}
    public record EnterpriseIntegrationReadiness(
        String state,
        String diagnosticCode,
        Boolean executionConfigured,
        Boolean verificationConfigured,
        Boolean credentialConfigured,
        String executionHost,
        String verificationHost,
        Boolean policyAllowsExecutionHost,
        Boolean policyAllowsVerificationHost,
        Boolean executorDelegationAllowsExecutionHost,
        Boolean executorDelegationAllowsVerificationHost,
        List<String> supportedExecutableActions,
        List<String> supportedVerifiedActions,
        List<EnterpriseVerificationContract> verificationContracts,
        List<String> evaluationOnlyActions,
        String checkedAt
    ) {
        public EnterpriseIntegrationReadiness {
            state = ENTERPRISE_INTEGRATION_STATES.contains(state) ? state : "UNKNOWN";
            diagnosticCode = ENTERPRISE_INTEGRATION_DIAGNOSTIC_CODES.contains(diagnosticCode)
                ? diagnosticCode
                : "TRUST_RUNTIME_UNAVAILABLE";
            executionHost = safeHostname(executionHost);
            verificationHost = safeHostname(verificationHost);
            supportedExecutableActions = safeList(supportedExecutableActions);
            supportedVerifiedActions = safeList(supportedVerifiedActions);
            verificationContracts = verificationContracts == null ? List.of() : List.copyOf(verificationContracts);
            evaluationOnlyActions = safeList(evaluationOnlyActions);
            boolean coherentReady = Boolean.TRUE.equals(executionConfigured)
                && Boolean.TRUE.equals(verificationConfigured)
                && Boolean.TRUE.equals(credentialConfigured)
                && executionHost != null
                && verificationHost != null
                && Boolean.TRUE.equals(policyAllowsExecutionHost)
                && Boolean.TRUE.equals(policyAllowsVerificationHost)
                && Boolean.TRUE.equals(executorDelegationAllowsExecutionHost)
                && Boolean.TRUE.equals(executorDelegationAllowsVerificationHost)
                && !supportedExecutableActions.isEmpty()
                && !supportedVerifiedActions.isEmpty();
            if ("READY".equals(state) && !coherentReady) {
                state = "UNKNOWN";
                diagnosticCode = "TRUST_RUNTIME_UNAVAILABLE";
            } else if ("UNKNOWN".equals(state)) {
                if ("NONE".equals(diagnosticCode)) diagnosticCode = "TRUST_RUNTIME_UNAVAILABLE";
            } else {
                diagnosticCode = "NONE";
            }
        }
    }
    @JsonIgnoreProperties(ignoreUnknown = true)
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
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ActivityPage(List<ActivityEvent> events, Long nextSequence, boolean complete) {
        public ActivityPage {
            events = events == null ? List.of() : List.copyOf(events);
        }
    }
}
