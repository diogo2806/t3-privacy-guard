package br.com.privacyguard.runtime.status;

import br.com.privacyguard.runtime.activity.ActivityLog;
import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.policy.AppliedPolicy;
import br.com.privacyguard.runtime.policy.PolicyDocumentException;
import br.com.privacyguard.runtime.policy.PolicyDocumentParser;
import br.com.privacyguard.runtime.remediation.RemediationRules;
import br.com.privacyguard.runtime.store.PolicyStore;
import br.com.privacyguard.runtime.store.PrivateConfigStore;
import br.com.privacyguard.runtime.store.PrivateProfileStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class RuntimeReadinessService {
    /** Same CONTRACT_VERSION as the Rust contract this runtime replaces. */
    public static final String CONTRACT_VERSION = "1.0.0";

    private final PolicyStore policies;
    private final PrivateConfigStore secrets;
    private final PrivateProfileStore profiles;
    private final ObjectMapper mapper;
    private final String tenantId;
    private final boolean allowInsecureHttp;

    public RuntimeReadinessService(
        PolicyStore policies,
        PrivateConfigStore secrets,
        PrivateProfileStore profiles,
        ObjectMapper mapper,
        @Value("${guard-runtime.tenant-id:default}") String tenantId,
        @Value("${guard-runtime.egress.allow-insecure-http:false}") boolean allowInsecureHttp
    ) {
        this.policies = policies;
        this.secrets = secrets;
        this.profiles = profiles;
        this.mapper = mapper;
        this.tenantId = tenantId == null || tenantId.isBlank() ? "default" : tenantId.trim();
        this.allowInsecureHttp = allowInsecureHttp;
    }

    public RuntimeReadiness readiness() {
        String policyState = "UNAVAILABLE";
        AppliedPolicy applied = null;
        Optional<byte[]> bytes = policies.current();
        if (bytes.isPresent()) {
            try {
                applied = PolicyDocumentParser.parse(bytes.get());
                policyState = "AVAILABLE";
            } catch (PolicyDocumentException ex) {
                policyState = "INVALID";
            }
        }

        boolean endpointsValid = true;
        String executionHost = null;
        String verificationHost = null;
        try {
            executionHost = secrets.get("security_api_url").map(url -> RemediationRules.extractEgressHost(url, allowInsecureHttp)).orElse(null);
            verificationHost = secrets.get("security_verification_url").map(url -> RemediationRules.extractEgressHost(url, allowInsecureHttp)).orElse(null);
        } catch (ContractRejectedException ex) {
            endpointsValid = false;
            executionHost = null;
            verificationHost = null;
        }

        String activeKey = secrets.get("remediation_auth_active_key_id").orElse(null);
        boolean verificationKeyConfigured = activeKey != null && secrets.get("remediation_auth_public_key_spki:" + activeKey).isPresent();

        return new RuntimeReadiness(
            ActivityLog.CONTRACT_ID,
            CONTRACT_VERSION,
            tenantId,
            policyState,
            applied == null ? null : applied.version(),
            applied == null ? null : applied.hash(),
            applied == null ? null : policyDocument(applied),
            endpointsValid,
            executionHost,
            verificationHost,
            allowInsecureHttp,
            secrets.get("security_api_key").isPresent(),
            verificationKeyConfigured,
            profiles.resolve(RemediationRules.VERIFIED_EMAIL_PATH).isPresent()
        );
    }

    private JsonNode policyDocument(AppliedPolicy applied) {
        try {
            return mapper.readTree(PolicyDocumentParser.canonicalBytes(applied.document()));
        } catch (IOException ex) {
            throw new IllegalStateException("canonical policy could not be re-read", ex);
        }
    }
}
