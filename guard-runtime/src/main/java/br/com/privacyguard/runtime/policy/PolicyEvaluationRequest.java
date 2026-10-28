package br.com.privacyguard.runtime.policy;

import java.util.List;

/** Wire format keeps the contract's field names (agent_did included) so the gateway can switch runtimes unchanged. */
public record PolicyEvaluationRequest(
    String requestId,
    String agentId,
    String action,
    String resource,
    String purpose,
    String host,
    List<String> fields,
    List<String> privateRefs
) {
    public PolicyEvaluationRequest {
        fields = List.copyOf(fields);
        privateRefs = List.copyOf(privateRefs);
    }
}
