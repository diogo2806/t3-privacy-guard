package br.com.privacyguard.runtime.remediation;

import br.com.privacyguard.runtime.contract.ContractText;
import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.contract.StrictJson;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Collections;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

/** Wire format of the contract's execute-remediation input (agent_did / executor_did names kept). */
public record RemediationExecutionRequest(
    String incidentId,
    String actionId,
    String decisionId,
    String requestId,
    String agentId,
    String executorId,
    String action,
    String resource,
    String purpose,
    String approvedHost,
    List<String> fields,
    SortedMap<String, String> normalPayload,
    List<String> privateRefs,
    String policyVersion,
    String policyHash,
    String authorizationProof
) {
    public RemediationExecutionRequest {
        fields = List.copyOf(fields);
        TreeMap<String, String> sorted = new TreeMap<>(ContractText.CODE_POINT_ORDER);
        sorted.putAll(normalPayload);
        normalPayload = Collections.unmodifiableSortedMap(sorted);
        privateRefs = List.copyOf(privateRefs);
    }

    public static RemediationExecutionRequest parse(byte[] input) {
        try {
            ObjectNode root = StrictJson.parseObject(input);
            return new RemediationExecutionRequest(
                StrictJson.requiredString(root, "incident_id"),
                StrictJson.requiredString(root, "action_id"),
                StrictJson.requiredString(root, "decision_id"),
                StrictJson.requiredString(root, "request_id"),
                StrictJson.requiredString(root, "agent_did"),
                StrictJson.requiredString(root, "executor_did"),
                StrictJson.requiredString(root, "action"),
                StrictJson.requiredString(root, "resource"),
                StrictJson.requiredString(root, "purpose"),
                StrictJson.requiredString(root, "approved_host"),
                StrictJson.stringList(root, "fields"),
                StrictJson.stringMap(root, "normal_payload"),
                StrictJson.stringList(root, "private_refs"),
                StrictJson.requiredString(root, "policy_version"),
                StrictJson.requiredString(root, "policy_hash"),
                StrictJson.requiredString(root, "authorization_proof")
            );
        } catch (InvalidContractInputException ex) {
            throw new InvalidContractInputException("execute-remediation: invalid JSON input");
        }
    }
}
