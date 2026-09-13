package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RemediationAuthorizationSignerTest {
    private static final String PRIVATE_KEY_PKCS8 = "MC4CAQAwBQYDK2VwBCIEIAv4OIfbF/R/i9uL6wgRalq2gperSKNx+Ig9BuS9L4qS";
    private static final String PUBLIC_KEY_SPKI = "MCowBQYDK2VwAyEAW3EwSatHmT/ZSgrqu/G3ecXJrTviA5SjAoCwIfwau6A=";
    private static final String POLICY_VERSION = "2026-09-12.1";
    private static final String POLICY_HASH = "a".repeat(64);
    private static final String EXECUTOR_DID = "did:t3n:protected-executor-test";
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void capabilityV2IsSignedAndBoundToActionPrivateReferencesPolicyDestinationPayloadAndExecutor() throws Exception {
        var signer = new RemediationAuthorizationSigner(mapper, PRIVATE_KEY_PKCS8, 60, () -> EXECUTOR_DID);
        Map<String, String> normalPayload = Map.of(
            "incident_id", "inc-demo-001",
            "reason", "suspected compromise",
            "credential_id", "cred-demo-001"
        );
        String token = signer.issue(
            "incident-1", "action-1", "request-1", "decision-1",
            "notify-security", "incident:test", "incident-notification", "Security-A.Example",
            List.of("summary", "incident_id", "severity"), normalPayload, List.of("verified_email"),
            POLICY_VERSION, POLICY_HASH
        );

        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(3);
        assertThat(parts[0]).isEqualTo("v2");
        var claims = mapper.readTree(Base64.getUrlDecoder().decode(parts[1]));
        assertThat(claims.get("incidentId").asText()).isEqualTo("incident-1");
        assertThat(claims.get("decisionId").asText()).isEqualTo("decision-1");
        assertThat(claims.get("approvedHost").asText()).isEqualTo("security-a.example");
        assertThat(claims.get("fieldsHash").asText()).hasSize(64);
        assertThat(claims.get("normalPayloadHash").asText()).isEqualTo(NormalPayloadCanonicalizer.sha256(normalPayload));
        assertThat(claims.get("privateRefsHash").asText()).hasSize(64);
        assertThat(claims.get("policyVersion").asText()).isEqualTo(POLICY_VERSION);
        assertThat(claims.get("policyHash").asText()).isEqualTo(POLICY_HASH);
        assertThat(claims.get("executorDid").asText()).isEqualTo(EXECUTOR_DID);
        assertThat(claims.get("nonce").asText()).isNotBlank();
        assertThat(claims.get("expiresAt").asLong()).isGreaterThan(claims.get("issuedAt").asLong());
        assertThat(claims.has("authorizedAt")).isFalse();

        var publicKey = KeyFactory.getInstance("Ed25519")
            .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY_SPKI)));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertThat(verifier.verify(Base64.getUrlDecoder().decode(parts[2]))).isTrue();
    }

    @Test
    void rejectsLegacySharedSecretInsteadOfEd25519PrivateKey() {
        assertThatThrownBy(() -> new RemediationAuthorizationSigner(
            mapper, "test-remediation-capability-key-1234567890", 60, () -> EXECUTOR_DID
        )).isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("REMEDIATION_AUTH_PRIVATE_KEY_PKCS8");
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
