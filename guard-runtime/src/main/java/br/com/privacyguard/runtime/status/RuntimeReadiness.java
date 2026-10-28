package br.com.privacyguard.runtime.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

/**
 * What the gateway needs to report integration readiness. Endpoints are reduced to hostnames: full URLs, the API
 * key and the verified email never leave the runtime.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record RuntimeReadiness(
    String contractId,
    String contractVersion,
    String tenantId,
    String policyState,
    String policyVersion,
    String policyHash,
    JsonNode policyDocument,
    boolean endpointConfigurationValid,
    String executionHost,
    String verificationHost,
    boolean insecureHttpAllowed,
    boolean credentialConfigured,
    boolean verificationKeyConfigured,
    boolean privateProfileConfigured
) {}
