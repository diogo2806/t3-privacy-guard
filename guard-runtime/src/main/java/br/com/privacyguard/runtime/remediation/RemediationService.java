package br.com.privacyguard.runtime.remediation;

import br.com.privacyguard.runtime.authorization.RemediationAuthorizer;
import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.CallerRegistry;
import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.egress.EgressException;
import br.com.privacyguard.runtime.egress.ProtectedEgress;
import br.com.privacyguard.runtime.policy.AppliedPolicy;
import br.com.privacyguard.runtime.policy.PolicyDocumentException;
import br.com.privacyguard.runtime.policy.PolicyDocumentParser;
import br.com.privacyguard.runtime.store.PolicyStore;
import br.com.privacyguard.runtime.store.PrivateConfigStore;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** execute_wasm and verify_wasm from remediation.rs, with the T3N host calls replaced by runtime stores. */
@Service
public class RemediationService {
    private final RemediationAuthorizer authorizer;
    private final PolicyStore policies;
    private final PrivateConfigStore secrets;
    private final ProtectedEgress egress;
    private final CallerRegistry callers;
    private final Clock clock;
    private final boolean allowInsecureHttp;

    public RemediationService(
        RemediationAuthorizer authorizer,
        PolicyStore policies,
        PrivateConfigStore secrets,
        ProtectedEgress egress,
        CallerRegistry callers,
        Clock clock,
        @Value("${guard-runtime.egress.allow-insecure-http:false}") boolean allowInsecureHttp
    ) {
        this.authorizer = authorizer;
        this.policies = policies;
        this.secrets = secrets;
        this.egress = egress;
        this.callers = callers;
        this.clock = clock;
        this.allowInsecureHttp = allowInsecureHttp;
    }

    public RemediationResult execute(RemediationExecutionRequest request, Caller executor) {
        RemediationRules.validateExecutionRequest(request, executor::hasId);
        String approvedHost = RemediationRules.canonicalizeApprovedHost(request.approvedHost());

        authorizer.verifyAndConsume(request, clock.millis());

        AppliedPolicy appliedPolicy = currentPolicy();
        RemediationRules.validatePolicyBinding(request, appliedPolicy);
        String apiUrl = requireSecret("security_api_url");
        String resolvedHost = RemediationRules.extractEgressHost(apiUrl, allowInsecureHttp);
        String host = RemediationRules.ensureExecutionDestination(approvedHost, resolvedHost);
        RemediationRules.MinimizedEgress minimized = RemediationRules.buildMinimizedEgress(
            request, appliedPolicy, host, executor::hasId, callers::isProposalAgent
        );

        String apiKey = requireSecret("security_api_key");
        Map<String, String> headers = headers(apiKey);
        headers.put("Idempotency-Key", minimized.effectiveRequest().requestId());
        ProtectedEgress.Response response = send(apiUrl, headers, minimized.body());
        if (response.code() < 200 || response.code() >= 300) {
            throw new ContractRejectedException("remediation upstream returned HTTP " + response.code());
        }
        return new RemediationResult(
            minimized.effectiveRequest().requestId(),
            "PENDING_VERIFICATION",
            response.code(),
            RemediationRules.extractOperationId(response.payload()),
            appliedPolicy.version(),
            appliedPolicy.hash()
        );
    }

    public RemediationVerificationResult verify(RemediationVerificationRequest request) {
        RemediationRules.validateVerificationRequest(request);
        String verificationUrl = requireSecret("security_verification_url");
        String apiKey = requireSecret("security_api_key");
        RemediationRules.extractEgressHost(verificationUrl, allowInsecureHttp);
        SortedMap<String, String> body = new TreeMap<>();
        body.put("request_id", request.requestId());
        body.put("operation_id", request.operationId());
        body.put("action", request.action());
        body.put("expected_state", request.expectedState());
        ProtectedEgress.Response response = send(verificationUrl, headers(apiKey), body);
        if (response.code() < 200 || response.code() >= 300) {
            throw new ContractRejectedException("verification upstream returned HTTP " + response.code());
        }
        return RemediationRules.verificationFromPayload(request, response.payload());
    }

    private AppliedPolicy currentPolicy() {
        byte[] bytes = policies.current()
            .orElseThrow(() -> new ContractRejectedException("versioned operational policy entry is missing"));
        try {
            return PolicyDocumentParser.parse(bytes);
        } catch (PolicyDocumentException ex) {
            throw new ContractRejectedException("versioned operational policy is invalid");
        }
    }

    private String requireSecret(String key) {
        return secrets.get(key).orElseThrow(() -> new ContractRejectedException("required private configuration " + key + " is missing"));
    }

    private static Map<String, String> headers(String apiKey) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + apiKey);
        headers.put("Accept", "application/json");
        headers.put("Content-Type", "application/json");
        return headers;
    }

    private ProtectedEgress.Response send(String url, Map<String, String> headers, SortedMap<String, String> body) {
        try {
            return egress.post(url, headers, body);
        } catch (EgressException ex) {
            throw new ContractRejectedException(switch (ex.kind()) {
                case EGRESS_DENIED -> "egress denied for host " + ex.getMessage();
                case PLACEHOLDER_DENIED -> "profile placeholder resolution was denied";
                case PLACEHOLDER_UNKNOWN -> "required verified profile value is unavailable";
                case PLACEHOLDER_NO_USER_CONTEXT -> "no user context for placeholder resolution";
                case UPSTREAM_ERROR -> "upstream transport failed";
            });
        }
    }
}
