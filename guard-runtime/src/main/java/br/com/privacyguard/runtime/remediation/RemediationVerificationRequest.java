package br.com.privacyguard.runtime.remediation;

import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.contract.StrictJson;
import com.fasterxml.jackson.databind.node.ObjectNode;

public record RemediationVerificationRequest(String requestId, String operationId, String action, String expectedState) {
    public static RemediationVerificationRequest parse(byte[] input) {
        try {
            ObjectNode root = StrictJson.parseObject(input);
            return new RemediationVerificationRequest(
                StrictJson.requiredString(root, "request_id"),
                StrictJson.requiredString(root, "operation_id"),
                StrictJson.requiredString(root, "action"),
                StrictJson.requiredString(root, "expected_state")
            );
        } catch (InvalidContractInputException ex) {
            throw new InvalidContractInputException("verify-remediation: invalid JSON input");
        }
    }
}
