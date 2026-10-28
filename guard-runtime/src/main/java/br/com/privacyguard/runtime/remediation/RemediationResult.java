package br.com.privacyguard.runtime.remediation;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/** Deliberately reduced: nothing from the upstream response except a validated opaque operation id. */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record RemediationResult(
    String requestId,
    String status,
    int httpCode,
    String operationId,
    String policyVersion,
    String policyHash
) {}
