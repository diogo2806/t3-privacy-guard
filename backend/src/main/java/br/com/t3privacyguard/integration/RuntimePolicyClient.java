package br.com.t3privacyguard.integration;

import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.integration.GuardRuntimeClient.Caller;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.springframework.stereotype.Component;

/** evaluate-action on guard-runtime, always as the proposal agent; the backend never lets a caller choose agent_did. */
@Component
public class RuntimePolicyClient {
    private final GuardRuntimeClient runtime;
    private final ObjectMapper mapper;

    public RuntimePolicyClient(GuardRuntimeClient runtime, ObjectMapper mapper) {
        this.runtime = runtime;
        this.mapper = mapper;
    }

    public RuntimeDecision evaluate(EvaluationRequest request) {
        ObjectNode body = mapper.valueToTree(request);
        body.put("agent_did", runtime.proposalAgentId());
        GuardRuntimeClient.Response response = runtime.post("/v1/functions/evaluate-action", Caller.PROPOSAL, body);
        if (!response.ok() || response.body() == null) {
            throw new TrustRuntimeUnavailableException("Policy evaluation is unavailable (guard-runtime HTTP " + response.status() + ")");
        }
        RuntimeDecision decision;
        try {
            decision = mapper.treeToValue(response.body(), RuntimeDecision.class);
        } catch (JsonProcessingException | IllegalArgumentException ex) {
            throw new TrustRuntimeUnavailableException("guard-runtime returned an invalid policy decision", ex);
        }
        if (decision == null || decision.decision() == null || decision.requestId() == null) {
            throw new TrustRuntimeUnavailableException("guard-runtime returned an incomplete policy decision");
        }
        return decision.withActivity(response.activitySequence(), response.activityHash());
    }

    public record EvaluationRequest(
        @JsonProperty("request_id") String requestId,
        String action,
        String resource,
        String purpose,
        String host,
        List<String> fields,
        @JsonProperty("private_refs") List<String> privateRefs
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record RuntimeDecision(
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
        @JsonProperty("requires_human_authorization") Boolean requiresHumanAuthorization,
        @JsonProperty("activity_sequence") Long activitySequence,
        @JsonProperty("activity_hash") String activityHash
    ) {
        public RuntimeDecision(
            String requestId,
            DecisionType decision,
            String reasonCode,
            String reason,
            List<String> allowedFields,
            List<String> redactedFields,
            List<String> allowedPrivateRefs,
            List<String> redactedPrivateRefs
        ) {
            this(requestId, decision, reasonCode, reason, allowedFields, redactedFields, allowedPrivateRefs, redactedPrivateRefs, null, null, null, null, null);
        }

        public RuntimeDecision(
            String requestId,
            DecisionType decision,
            String reasonCode,
            String reason,
            List<String> allowedFields,
            List<String> redactedFields,
            List<String> allowedPrivateRefs,
            List<String> redactedPrivateRefs,
            String policyVersion,
            String policyHash,
            Boolean requiresHumanAuthorization
        ) {
            this(requestId, decision, reasonCode, reason, allowedFields, redactedFields, allowedPrivateRefs, redactedPrivateRefs,
                policyVersion, policyHash, requiresHumanAuthorization, null, null);
        }

        RuntimeDecision withActivity(Long sequence, String hash) {
            return new RuntimeDecision(requestId, decision, reasonCode, reason, allowedFields, redactedFields, allowedPrivateRefs,
                redactedPrivateRefs, policyVersion, policyHash, requiresHumanAuthorization, sequence, hash);
        }
    }
}
