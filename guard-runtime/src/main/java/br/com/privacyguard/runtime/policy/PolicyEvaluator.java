package br.com.privacyguard.runtime.policy;

import br.com.privacyguard.runtime.contract.ContractText;
import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.contract.StrictJson;
import br.com.privacyguard.runtime.policy.PolicyDecision.Decision;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.TreeSet;
import java.util.function.Predicate;

/**
 * Port of policy.rs evaluate-action. Reason codes and decision semantics are unchanged. The agent check is the one
 * intentional difference: the contract accepted any "did:t3n:" prefix because T3N had already authenticated the
 * caller; here the runtime passes a predicate bound to the caller it authenticated itself.
 */
public final class PolicyEvaluator {
    private static final int MAX_REQUEST_ID_LEN = 128;

    private PolicyEvaluator() {}

    public static PolicyEvaluationRequest parseRequest(byte[] input) {
        try {
            ObjectNode root = StrictJson.parseObject(input);
            return new PolicyEvaluationRequest(
                StrictJson.requiredString(root, "request_id"),
                StrictJson.requiredString(root, "agent_did"),
                StrictJson.requiredString(root, "action"),
                StrictJson.requiredString(root, "resource"),
                StrictJson.requiredString(root, "purpose"),
                StrictJson.optionalString(root, "host"),
                StrictJson.stringList(root, "fields"),
                StrictJson.stringList(root, "private_refs")
            );
        } catch (InvalidContractInputException ex) {
            throw new InvalidContractInputException("evaluate-action: invalid JSON input");
        }
    }

    public static PolicyDecision evaluate(PolicyEvaluationRequest request, Optional<byte[]> policyBytes, Predicate<String> isAuthenticatedAgent) {
        String requestId = ContractText.trim(request.requestId());
        if (policyBytes.isEmpty()) {
            return deny(requestId, "POLICY_UNAVAILABLE", "Versioned operational policy is unavailable", null, false);
        }
        AppliedPolicy applied;
        try {
            applied = PolicyDocumentParser.parse(policyBytes.get());
        } catch (PolicyDocumentException ex) {
            return deny(requestId, "POLICY_INVALID", "Versioned operational policy is invalid", null, false);
        }
        return evaluate(request, applied, isAuthenticatedAgent);
    }

    public static PolicyDecision evaluate(PolicyEvaluationRequest request, AppliedPolicy applied, Predicate<String> isAuthenticatedAgent) {
        String requestId = ContractText.trim(request.requestId());
        if (requestId.isEmpty() || ContractText.utf8Length(requestId) > MAX_REQUEST_ID_LEN) {
            return deny(requestId, "INVALID_REQUEST_ID", "Request id is required and must be at most 128 characters", applied, false);
        }
        if (!isAuthenticatedAgent.test(ContractText.trim(request.agentId()))) {
            return deny(requestId, "INVALID_AGENT_DID", "Agent identity must match the authenticated caller", applied, false);
        }
        if (ContractText.trim(request.resource()).isEmpty()) {
            return deny(requestId, "INVALID_RESOURCE", "Resource is required", applied, false);
        }

        PolicyDocument.ActionPolicy rule = applied.document().actions().get(ContractText.normalized(request.action()));
        if (rule == null) {
            return deny(requestId, "ACTION_NOT_ALLOWED", "Requested action is not enabled by the active policy", applied, false);
        }
        boolean requiresHumanAuthorization = rule.requiresHumanAuthorization();
        if (!ContractText.normalized(request.purpose()).equals(rule.purpose())) {
            return deny(requestId, "PURPOSE_NOT_ALLOWED", "Declared purpose does not authorize this action", applied, requiresHumanAuthorization);
        }

        TreeSet<String> requestedFields = normalizedSet(request.fields());
        if (requestedFields.stream().anyMatch(PolicyDocumentParser.FORBIDDEN_SECRET_FIELDS::contains)) {
            return deny(requestId, "SECRET_DISCLOSURE_FORBIDDEN", "Direct disclosure of secrets or high-risk credentials is forbidden", applied, requiresHumanAuthorization);
        }

        TreeSet<String> requestedPrivateRefs = normalizedSet(request.privateRefs());
        if (requestedPrivateRefs.stream().anyMatch(value -> value.contains("{{") || value.contains("}}") || value.startsWith("profile."))) {
            return deny(requestId, "RAW_PLACEHOLDER_FORBIDDEN", "Clients must use logical private-data references, not raw placeholder strings", applied, requiresHumanAuthorization);
        }
        if (requestedPrivateRefs.stream().anyMatch(value -> !PolicyDocumentParser.KNOWN_PRIVATE_REFS.contains(value))) {
            return deny(requestId, "PRIVATE_REFERENCE_UNKNOWN", "Requested private-data reference is not recognized by the contract", applied, requiresHumanAuthorization);
        }

        String host = request.host() == null ? null : ContractText.normalized(request.host());
        if (host != null && host.isEmpty()) host = null;
        if (rule.requiresHost()) {
            if (host == null) {
                return deny(requestId, "HOST_REQUIRED", "This action requires an explicitly authorized destination host", applied, requiresHumanAuthorization);
            }
            if (!PolicyDocumentParser.validHost(host) || !rule.allowedHosts().contains(host)) {
                return deny(requestId, "HOST_NOT_ALLOWED", "Destination host is outside the active policy allowlist", applied, requiresHumanAuthorization);
            }
        } else if (host != null) {
            return deny(requestId, "UNEXPECTED_EGRESS", "This action does not require outbound network access", applied, requiresHumanAuthorization);
        }

        List<String> allowedFields = new ArrayList<>();
        List<String> redactedFields = new ArrayList<>();
        for (String field : requestedFields) {
            (rule.allowedFields().contains(field) ? allowedFields : redactedFields).add(field);
        }
        List<String> allowedPrivateRefs = new ArrayList<>();
        List<String> redactedPrivateRefs = new ArrayList<>();
        for (String privateRef : requestedPrivateRefs) {
            (rule.allowedPrivateRefs().contains(privateRef) ? allowedPrivateRefs : redactedPrivateRefs).add(privateRef);
        }

        boolean requiresMinimization = !redactedFields.isEmpty() || !redactedPrivateRefs.isEmpty();
        return new PolicyDecision(
            requestId,
            requiresMinimization ? Decision.REDACT : Decision.ALLOW,
            requiresMinimization ? "DATA_MINIMIZATION_REQUIRED" : "POLICY_ALLOW",
            requiresMinimization
                ? "Action is allowed only after removing data or private references unnecessary for the declared purpose"
                : "Action and requested data satisfy the active versioned policy",
            allowedFields,
            redactedFields,
            allowedPrivateRefs,
            redactedPrivateRefs,
            applied.version(),
            applied.hash(),
            requiresHumanAuthorization
        );
    }

    private static TreeSet<String> normalizedSet(List<String> values) {
        TreeSet<String> result = new TreeSet<>(ContractText.CODE_POINT_ORDER);
        for (String value : values) {
            String normalized = ContractText.normalized(value);
            if (!normalized.isEmpty()) result.add(normalized);
        }
        return result;
    }

    private static PolicyDecision deny(String requestId, String code, String reason, AppliedPolicy applied, boolean requiresHumanAuthorization) {
        return new PolicyDecision(
            requestId,
            Decision.DENY,
            code,
            reason,
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            applied == null ? null : applied.version(),
            applied == null ? null : applied.hash(),
            requiresHumanAuthorization
        );
    }
}
