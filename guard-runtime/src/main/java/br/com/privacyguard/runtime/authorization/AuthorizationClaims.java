package br.com.privacyguard.runtime.authorization;

import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.contract.StrictJson;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Claims of the v2 one-time remediation capability signed by the backend after human authorization. */
public record AuthorizationClaims(
    String keyId,
    String incidentId,
    String actionId,
    String requestId,
    String decisionId,
    String action,
    String resource,
    String purpose,
    String approvedHost,
    String fieldsHash,
    String normalPayloadHash,
    String privateRefsHash,
    String policyVersion,
    String policyHash,
    String executorId,
    String operatorPrincipalHash,
    long authorizedAt,
    long issuedAt,
    long expiresAt,
    String nonce
) {
    /** Unknown claims are ignored and every listed claim is required, matching the Rust struct. */
    static AuthorizationClaims parse(byte[] json) {
        ObjectNode root = StrictJson.parseObject(json);
        return new AuthorizationClaims(
            StrictJson.requiredString(root, "keyId"),
            StrictJson.requiredString(root, "incidentId"),
            StrictJson.requiredString(root, "actionId"),
            StrictJson.requiredString(root, "requestId"),
            StrictJson.requiredString(root, "decisionId"),
            StrictJson.requiredString(root, "action"),
            StrictJson.requiredString(root, "resource"),
            StrictJson.requiredString(root, "purpose"),
            StrictJson.requiredString(root, "approvedHost"),
            StrictJson.requiredString(root, "fieldsHash"),
            StrictJson.requiredString(root, "normalPayloadHash"),
            StrictJson.requiredString(root, "privateRefsHash"),
            StrictJson.requiredString(root, "policyVersion"),
            StrictJson.requiredString(root, "policyHash"),
            StrictJson.requiredString(root, "executorDid"),
            StrictJson.requiredString(root, "operatorPrincipalHash"),
            StrictJson.requiredUnsignedLong(root, "authorizedAt"),
            StrictJson.requiredUnsignedLong(root, "issuedAt"),
            StrictJson.requiredUnsignedLong(root, "expiresAt"),
            StrictJson.requiredString(root, "nonce")
        );
    }

    static AuthorizationClaims parseOrNull(byte[] json) {
        try {
            return parse(json);
        } catch (InvalidContractInputException ex) {
            return null;
        }
    }
}
