package br.com.privacyguard.runtime.remediation;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/** observed_state is always present (possibly null); the two optional fields are omitted when absent, as in serde. */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record RemediationVerificationResult(
    String requestId,
    String status,
    String observedState,
    @JsonInclude(JsonInclude.Include.NON_NULL) Boolean recipientResolved,
    @JsonInclude(JsonInclude.Include.NON_NULL) PayloadMinimizationProof payloadProof
) {
    @JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
    public record PayloadMinimizationProof(boolean mustEgressSeen, boolean mustNotEgressSeen) {}
}
