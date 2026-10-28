package br.com.privacyguard.runtime.policy;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import java.util.List;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record PolicyDecision(
    String requestId,
    Decision decision,
    String reasonCode,
    String reason,
    List<String> allowedFields,
    List<String> redactedFields,
    List<String> allowedPrivateRefs,
    List<String> redactedPrivateRefs,
    String policyVersion,
    String policyHash,
    boolean requiresHumanAuthorization
) {
    public enum Decision { ALLOW, REDACT, DENY }

    public PolicyDecision {
        allowedFields = List.copyOf(allowedFields);
        redactedFields = List.copyOf(redactedFields);
        allowedPrivateRefs = List.copyOf(allowedPrivateRefs);
        redactedPrivateRefs = List.copyOf(redactedPrivateRefs);
    }
}
