package br.com.privacyguard.runtime.remediation;

import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.contract.ContractText;
import br.com.privacyguard.runtime.contract.Hostnames;
import br.com.privacyguard.runtime.contract.StrictJson;
import br.com.privacyguard.runtime.policy.AppliedPolicy;
import br.com.privacyguard.runtime.policy.PolicyDecision;
import br.com.privacyguard.runtime.policy.PolicyDecision.Decision;
import br.com.privacyguard.runtime.policy.PolicyEvaluationRequest;
import br.com.privacyguard.runtime.policy.PolicyEvaluator;
import br.com.privacyguard.runtime.remediation.RemediationVerificationResult.PayloadMinimizationProof;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/** Port of the target-independent part of remediation.rs. Error texts are the contract's. */
public final class RemediationRules {
    public static final String VERIFIED_EMAIL_MARKER = "{{profile.verified_contacts.email.value}}";
    static final String REVOKE_CREDENTIAL_ACTION = "revoke-credential";
    static final String NOTIFY_SECURITY_ACTION = "notify-security";
    private static final int MAX_NORMAL_PAYLOAD_ENTRIES = 16;
    private static final int MAX_NORMAL_VALUE_BYTES = 512;
    private static final int MAX_AUTHORIZATION_PROOF_BYTES = 8_192;
    private static final Pattern NORMAL_KEY = Pattern.compile("[a-z][a-z0-9_]{0,79}");
    private static final Pattern OPERATION_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_-]{0,127}");
    private static final Set<String> FORBIDDEN_NORMAL_PAYLOAD_KEYS = Set.of(
        "api_key", "card_number", "credential", "cpf", "password", "private_key", "secret", "ssn", "token"
    );
    private static final List<String> REVOKE_REQUIRED_NORMAL_FIELDS = List.of("incident_id", "credential_id", "reason");
    private static final List<String> NOTIFY_REQUIRED_NORMAL_FIELDS = List.of("incident_id", "severity", "summary");
    private static final String NOT_IMPLEMENTED = "protected remediation executor is not implemented for this action";
    private static final String DESTINATION_ERROR = "approved remediation destination is not a valid hostname";

    private RemediationRules() {}

    public record MinimizedEgress(SortedMap<String, String> body, PolicyEvaluationRequest effectiveRequest) {}

    static List<String> requiredNormalFields(String action) {
        return switch (action) {
            case REVOKE_CREDENTIAL_ACTION -> REVOKE_REQUIRED_NORMAL_FIELDS;
            case NOTIFY_SECURITY_ACTION -> NOTIFY_REQUIRED_NORMAL_FIELDS;
            default -> throw new ContractRejectedException(NOT_IMPLEMENTED);
        };
    }

    static void validateNormalPayload(RemediationExecutionRequest request) {
        if (request.normalPayload().isEmpty() || request.normalPayload().size() > MAX_NORMAL_PAYLOAD_ENTRIES) {
            throw new ContractRejectedException("trusted normal payload is missing or exceeds the item limit");
        }
        Set<String> requestedFields = new TreeSet<>(ContractText.CODE_POINT_ORDER);
        for (String field : request.fields()) requestedFields.add(ContractText.normalized(field));
        for (Map.Entry<String, String> entry : request.normalPayload().entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (!NORMAL_KEY.matcher(key).matches() || !key.equals(ContractText.normalized(key))) {
                throw new ContractRejectedException("trusted normal payload contains an invalid key");
            }
            if (FORBIDDEN_NORMAL_PAYLOAD_KEYS.contains(key)) {
                throw new ContractRejectedException("trusted normal payload contains a forbidden secret field");
            }
            if (ContractText.trim(value).isEmpty() || ContractText.utf8Length(value) > MAX_NORMAL_VALUE_BYTES) {
                throw new ContractRejectedException("trusted normal payload contains an invalid value");
            }
            if (!requestedFields.contains(key)) {
                throw new ContractRejectedException("trusted normal payload contains a field that was not requested");
            }
        }
    }

    /** The contract required a did:t3n: executor; here the executor must be the caller the runtime authenticated. */
    public static void validateExecutionRequest(RemediationExecutionRequest request, Predicate<String> isAuthenticatedExecutor) {
        switch (request.action()) {
            case REVOKE_CREDENTIAL_ACTION -> {
                if (!request.purpose().equals("incident-remediation") || !request.privateRefs().isEmpty()) {
                    throw new ContractRejectedException("revoke-credential executor received an invalid closed execution contract");
                }
            }
            case NOTIFY_SECURITY_ACTION -> {
                if (!request.purpose().equals("incident-notification")
                    || request.privateRefs().size() != 1
                    || !request.privateRefs().get(0).equals("verified_email")) {
                    throw new ContractRejectedException("notify-security requires exactly the logical private reference verified_email for incident-notification");
                }
            }
            default -> throw new ContractRejectedException(NOT_IMPLEMENTED);
        }
        Map<String, String> required = new LinkedHashMap<>();
        required.put("incident_id", request.incidentId());
        required.put("action_id", request.actionId());
        required.put("decision_id", request.decisionId());
        required.put("request_id", request.requestId());
        required.put("agent_did", request.agentId());
        required.put("executor_did", request.executorId());
        required.put("resource", request.resource());
        required.put("purpose", request.purpose());
        for (Map.Entry<String, String> entry : required.entrySet()) {
            if (ContractText.trim(entry.getValue()).isEmpty()) {
                throw new ContractRejectedException(entry.getKey() + " is required for protected remediation");
            }
        }
        if (!isAuthenticatedExecutor.test(request.executorId())) {
            throw new ContractRejectedException("protected executor DID is invalid");
        }
        if (request.authorizationProof().isEmpty() || ContractText.utf8Length(request.authorizationProof()) > MAX_AUTHORIZATION_PROOF_BYTES) {
            throw new ContractRejectedException("one-time authorization proof is required for protected remediation");
        }
        Hostnames.canonicalize(request.approvedHost(), DESTINATION_ERROR);
        validateNormalPayload(request);
    }

    static String expectedStateForAction(String action) {
        return switch (action) {
            case REVOKE_CREDENTIAL_ACTION -> "REVOKED";
            case NOTIFY_SECURITY_ACTION -> "DELIVERED";
            default -> throw new ContractRejectedException("verification action is not supported");
        };
    }

    static boolean validOperationId(String value) {
        return value != null && OPERATION_ID.matcher(value).matches();
    }

    public static void validateVerificationRequest(RemediationVerificationRequest request) {
        if (ContractText.trim(request.requestId()).isEmpty() || ContractText.trim(request.operationId()).isEmpty()) {
            throw new ContractRejectedException("verification identifiers are required");
        }
        if (!validOperationId(request.operationId())) {
            throw new ContractRejectedException("verification operation id is not a safe opaque identifier");
        }
        if (!request.expectedState().equals(expectedStateForAction(request.action()))) {
            throw new ContractRejectedException("verification expected_state does not match the remediation action");
        }
    }

    public static void validatePolicyBinding(RemediationExecutionRequest request, AppliedPolicy applied) {
        if (ContractText.trim(request.policyVersion()).isEmpty() || ContractText.utf8Length(request.policyHash()) != 64) {
            throw new ContractRejectedException("approved policy metadata is required for remediation");
        }
        if (!request.policyVersion().equals(applied.version()) || !request.policyHash().equals(applied.hash())) {
            throw new ContractRejectedException("active policy changed after authorization; remediation must be re-evaluated");
        }
    }

    public static String canonicalizeApprovedHost(String value) {
        return Hostnames.canonicalize(value, DESTINATION_ERROR);
    }

    /** extract_https_host; plain http only when the runtime is explicitly configured for local development. */
    public static String extractEgressHost(String url, boolean allowInsecureHttp) {
        String rest;
        if (url.startsWith("https://")) rest = url.substring("https://".length());
        else if (allowInsecureHttp && url.startsWith("http://")) rest = url.substring("http://".length());
        else throw new ContractRejectedException("security endpoint must use https");
        int slash = rest.indexOf('/');
        String host = slash < 0 ? rest : rest.substring(0, slash);
        try {
            return Hostnames.canonicalize(host, "security endpoint contains an invalid host");
        } catch (ContractRejectedException ex) {
            throw new ContractRejectedException("security endpoint contains an invalid host");
        }
    }

    public static String ensureExecutionDestination(String approvedHost, String actualHost) {
        String approved = Hostnames.canonicalize(approvedHost, DESTINATION_ERROR);
        String actual = Hostnames.canonicalize(actualHost, "security endpoint contains an invalid host");
        if (!approved.equals(actual)) throw new ContractRejectedException("EXECUTION_DESTINATION_CHANGED");
        return actual;
    }

    static String profileMarker(String logicalRef) {
        if (logicalRef.equals("verified_email")) return VERIFIED_EMAIL_MARKER;
        throw new ContractRejectedException("private-data reference is not mapped by this contract");
    }

    public static String extractOperationId(byte[] payload) {
        ObjectNode parsed = StrictJson.parseObjectOrNull(payload);
        if (parsed == null) return null;
        JsonNode value = parsed.get("operation_id");
        return value != null && value.isTextual() && validOperationId(value.textValue()) ? value.textValue() : null;
    }

    private static PayloadMinimizationProof extractPayloadProof(ObjectNode parsed) {
        JsonNode proof = parsed.get("payload_proof");
        if (proof == null || !proof.isObject()) return null;
        JsonNode mustEgress = proof.get("must_egress_seen");
        JsonNode mustNotEgress = proof.get("must_not_egress_seen");
        if (mustEgress == null || !mustEgress.isBoolean() || mustNotEgress == null || !mustNotEgress.isBoolean()) return null;
        return new PayloadMinimizationProof(mustEgress.booleanValue(), mustNotEgress.booleanValue());
    }

    /** Only the operation id, state, recipient flag and boolean payload proof are read back; nothing else escapes. */
    public static RemediationVerificationResult verificationFromPayload(RemediationVerificationRequest request, byte[] payload) {
        ObjectNode parsed = StrictJson.parseObjectOrNull(payload);
        String observedOperation = textOrNull(parsed, "operation_id");
        String observedState = textOrNull(parsed, "state");
        JsonNode recipientNode = parsed == null ? null : parsed.get("recipient_resolved");
        Boolean recipientResolved = recipientNode != null && recipientNode.isBoolean() ? recipientNode.booleanValue() : null;
        PayloadMinimizationProof payloadProof = parsed == null ? null : extractPayloadProof(parsed);
        boolean privateResolutionVerified = !request.action().equals(NOTIFY_SECURITY_ACTION) || Boolean.TRUE.equals(recipientResolved);
        boolean verified = request.operationId().equals(observedOperation)
            && request.expectedState().equals(observedState)
            && privateResolutionVerified;
        return new RemediationVerificationResult(
            request.requestId(), verified ? "VERIFIED" : "UNVERIFIED", observedState, recipientResolved, payloadProof
        );
    }

    static PolicyEvaluationRequest originalPolicyRequest(RemediationExecutionRequest request, String host) {
        return new PolicyEvaluationRequest(
            request.requestId(), request.agentId(), request.action(), request.resource(), request.purpose(), host,
            request.fields(), request.privateRefs()
        );
    }

    private static SortedMap<String, String> minimizedPayload(RemediationExecutionRequest request, PolicyDecision decision) {
        if (decision.decision() == Decision.DENY) throw new ContractRejectedException("remediation denied: " + decision.reasonCode());
        Set<String> allowed = Set.copyOf(decision.allowedFields());
        for (String required : requiredNormalFields(request.action())) {
            if (!allowed.contains(required)) {
                throw new ContractRejectedException("remediation denied: required field " + required + " was not allowed");
            }
            if (!request.normalPayload().containsKey(required)) {
                throw new ContractRejectedException("remediation denied: trusted payload is missing required field " + required);
            }
        }
        SortedMap<String, String> result = new TreeMap<>(ContractText.CODE_POINT_ORDER);
        request.normalPayload().forEach((key, value) -> {
            if (allowed.contains(key)) result.put(key, value);
        });
        return result;
    }

    /**
     * Re-evaluates the policy on the execution request, keeps only allowed normal values, re-checks the minimized
     * request and builds the outbound body with the private reference as a placeholder marker.
     */
    public static MinimizedEgress buildMinimizedEgress(
        RemediationExecutionRequest request,
        AppliedPolicy appliedPolicy,
        String host,
        Predicate<String> isAuthenticatedExecutor,
        Predicate<String> isProposalAgent
    ) {
        validateExecutionRequest(request, isAuthenticatedExecutor);
        validatePolicyBinding(request, appliedPolicy);

        PolicyEvaluationRequest requested = originalPolicyRequest(request, host);
        PolicyDecision initialDecision = PolicyEvaluator.evaluate(requested, appliedPolicy, isProposalAgent);
        SortedMap<String, String> normalPayload = minimizedPayload(request, initialDecision);
        if (request.action().equals(NOTIFY_SECURITY_ACTION) && !initialDecision.allowedPrivateRefs().equals(List.of("verified_email"))) {
            throw new ContractRejectedException("remediation denied: verified_email was not allowed for private notification");
        }

        PolicyEvaluationRequest effectiveRequest = new PolicyEvaluationRequest(
            requested.requestId(), requested.agentId(), requested.action(), requested.resource(), requested.purpose(), requested.host(),
            initialDecision.allowedFields(), initialDecision.allowedPrivateRefs()
        );
        PolicyDecision effectiveDecision = PolicyEvaluator.evaluate(effectiveRequest, appliedPolicy, isProposalAgent);
        if (effectiveDecision.decision() != Decision.ALLOW) {
            throw new ContractRejectedException("remediation denied after minimization: " + effectiveDecision.reasonCode());
        }

        SortedMap<String, String> body = new TreeMap<>(ContractText.CODE_POINT_ORDER);
        body.put("request_id", request.requestId());
        body.put("action", request.action());
        body.put("resource", request.resource());
        body.put("purpose", request.purpose());
        body.putAll(normalPayload);
        for (String logicalRef : effectiveRequest.privateRefs()) {
            String marker = profileMarker(logicalRef);
            if (!logicalRef.equals("verified_email")) throw new ContractRejectedException("private-data reference has no output mapping");
            body.put("recipient", marker);
        }
        return new MinimizedEgress(body, effectiveRequest);
    }

    private static String textOrNull(ObjectNode parsed, String field) {
        if (parsed == null) return null;
        JsonNode value = parsed.get(field);
        return value != null && value.isTextual() ? value.textValue() : null;
    }
}
