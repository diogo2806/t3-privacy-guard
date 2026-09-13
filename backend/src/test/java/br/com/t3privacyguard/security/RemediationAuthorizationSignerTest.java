package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class RemediationAuthorizationSignerTest {
    private static final String KEY = "test-remediation-capability-key-1234567890";
    private static final String POLICY_VERSION = "2026-09-12.1";
    private static final String POLICY_HASH = "a".repeat(64);
    private static final String EXECUTOR_DID = "did:t3n:protected-executor-test";
    private static final String OPERATOR = "ops-reviewer";
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void capabilityIsSignedAndBoundToActionPrivateReferencesPolicyDestinationPayloadOperatorAndExecutor() throws Exception {
        var signer = new RemediationAuthorizationSigner(mapper, KEY, 60, () -> EXECUTOR_DID);
        Map<String, String> normalPayload = Map.of(
            "incident_id", "inc-demo-001",
            "reason", "suspected compromise",
            "credential_id", "cred-demo-001"
        );
        Instant authorizationAt = Instant.now().minusSeconds(5);
        String token = signer.issue(
            "incident-1", "action-1", "request-1", "decision-1",
            "notify-security", "incident:test", "incident-notification", "Security-A.Example",
            List.of("summary", "incident_id", "severity"), normalPayload, List.of("verified_email"),
            POLICY_VERSION, POLICY_HASH, OPERATOR, authorizationAt
        );

        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(2);
        var claims = mapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
        assertThat(claims.get("incidentId").asText()).isEqualTo("incident-1");
        assertThat(claims.get("decisionId").asText()).isEqualTo("decision-1");
        assertThat(claims.get("approvedHost").asText()).isEqualTo("security-a.example");
        assertThat(claims.get("fieldsHash").asText()).hasSize(64);
        assertThat(claims.get("normalPayloadHash").asText()).isEqualTo(NormalPayloadCanonicalizer.sha256(normalPayload));
        assertThat(claims.get("privateRefsHash").asText()).hasSize(64);
        assertThat(claims.get("policyVersion").asText()).isEqualTo(POLICY_VERSION);
        assertThat(claims.get("policyHash").asText()).isEqualTo(POLICY_HASH);
        assertThat(claims.get("executorDid").asText()).isEqualTo(EXECUTOR_DID);
        assertThat(claims.get("operatorPrincipalHash").asText()).isEqualTo(OperatorPrincipalBinding.sha256(OPERATOR));
        assertThat(claims.get("authorizedAt").asLong()).isEqualTo(authorizationAt.toEpochMilli());
        assertThat(claims.get("issuedAt").asLong()).isGreaterThanOrEqualTo(claims.get("authorizedAt").asLong());
        assertThat(claims.get("expiresAt").asLong()).isGreaterThan(claims.get("issuedAt").asLong());
        assertThat(claims.get("nonce").asText()).isNotBlank();

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String expected = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(mac.doFinal(parts[0].getBytes(StandardCharsets.US_ASCII)));
        assertThat(parts[1]).isEqualTo(expected);
    }

    @Test
    void rejectsMissingInvalidOrFutureHumanAuthorizationProvenance() {
        var signer = new RemediationAuthorizationSigner(mapper, KEY, 60, () -> EXECUTOR_DID);
        Map<String, String> payload = Map.of("incident_id", "inc-demo-001", "credential_id", "cred-demo-001", "reason", "compromise");
        assertThatThrownBy(() -> signer.issue(
            "incident-1", "action-1", "request-1", "decision-1", "revoke-credential", "credential:test", "incident-remediation",
            "security-a.example", List.of("incident_id", "credential_id", "reason"), payload, List.of(), POLICY_VERSION, POLICY_HASH, null, Instant.now()
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> signer.issue(
            "incident-1", "action-1", "request-1", "decision-1", "revoke-credential", "credential:test", "incident-remediation",
            "security-a.example", List.of("incident_id", "credential_id", "reason"), payload, List.of(), POLICY_VERSION, POLICY_HASH, "anonymousUser", Instant.now()
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> signer.issue(
            "incident-1", "action-1", "request-1", "decision-1", "revoke-credential", "credential:test", "incident-remediation",
            "security-a.example", List.of("incident_id", "credential_id", "reason"), payload, List.of(), POLICY_VERSION, POLICY_HASH, OPERATOR, Instant.now().plusSeconds(10)
        )).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void destinationCanonicalizationRejectsUrlsPortsCredentialsAndInvalidDns() {
        assertThat(RemediationAuthorizationSigner.canonicalizeHost("Security-A.Example")).isEqualTo("security-a.example");
        assertThatThrownBy(() -> RemediationAuthorizationSigner.canonicalizeHost("https://security-a.example/remediate"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RemediationAuthorizationSigner.canonicalizeHost("security-a.example:443"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RemediationAuthorizationSigner.canonicalizeHost("user@security-a.example"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RemediationAuthorizationSigner.canonicalizeHost("-invalid.example"))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
