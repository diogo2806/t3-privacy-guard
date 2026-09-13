package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class RemediationAuthorizationSignerTest {
    private static final String POLICY_VERSION = "2026-09-12.1";
    private static final String POLICY_HASH = "a".repeat(64);
    private static final String EXECUTOR_DID = "did:t3n:protected-executor-test";
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void capabilityIsEd25519SignedVersionedAndBoundToActionPrivateReferencesPolicyDestinationAndExecutor() throws Exception {
        KeyPair keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var signer = new RemediationAuthorizationSigner(
            mapper,
            Base64.getEncoder().encodeToString(keys.getPrivate().getEncoded()),
            rawPublicKeyHex(keys),
            "test-v2",
            60,
            () -> EXECUTOR_DID
        );
        String token = signer.issue(
            "incident-1", "action-1", "request-1", "decision-1",
            "notify-security", "incident:test", "incident-notification", "Security-A.Example",
            List.of("summary", "incident_id", "severity"), List.of("verified_email"),
            POLICY_VERSION, POLICY_HASH
        );

        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(3);
        assertThat(parts[0]).isEqualTo("v2");
        assertThat(parts[2]).matches("[a-f0-9]{128}");
        var claims = mapper.readTree(Base64.getUrlDecoder().decode(parts[1]));
        assertThat(claims.get("keyId").asText()).isEqualTo("test-v2");
        assertThat(claims.get("incidentId").asText()).isEqualTo("incident-1");
        assertThat(claims.get("decisionId").asText()).isEqualTo("decision-1");
        assertThat(claims.get("approvedHost").asText()).isEqualTo("security-a.example");
        assertThat(claims.get("fieldsHash").asText()).hasSize(64);
        assertThat(claims.get("privateRefsHash").asText()).hasSize(64);
        assertThat(claims.get("policyVersion").asText()).isEqualTo(POLICY_VERSION);
        assertThat(claims.get("policyHash").asText()).isEqualTo(POLICY_HASH);
        assertThat(claims.get("executorDid").asText()).isEqualTo(EXECUTOR_DID);
        assertThat(claims.get("nonce").asText()).isNotBlank();
        assertThat(claims.get("expiresAt").asLong()).isGreaterThan(claims.get("issuedAt").asLong());
        assertThat(claims.get("expiresAt").asLong() - claims.get("issuedAt").asLong()).isEqualTo(60);

        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(keys.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertThat(verifier.verify(HexFormat.of().parseHex(parts[2]))).isTrue();
    }

    @Test
    void constructorRejectsMismatchedSigningAndVerificationKeys() throws Exception {
        KeyPair signing = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        KeyPair other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        assertThatThrownBy(() -> new RemediationAuthorizationSigner(
            mapper,
            Base64.getEncoder().encodeToString(signing.getPrivate().getEncoded()),
            rawPublicKeyHex(other),
            "test-v2",
            60,
            () -> EXECUTOR_DID
        )).isInstanceOf(IllegalStateException.class).hasMessageContaining("do not form a pair");
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

    private static String rawPublicKeyHex(KeyPair keys) {
        byte[] encoded = keys.getPublic().getEncoded();
        return HexFormat.of().formatHex(Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length));
    }
}
