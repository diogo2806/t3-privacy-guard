package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class RemediationAuthorizationSignerTest {
    private static final KeyPair TEST_KEY_PAIR = generateKeyPair();
    private static final String PRIVATE_KEY_PKCS8 = Base64.getEncoder().encodeToString(TEST_KEY_PAIR.getPrivate().getEncoded());
    private static final String PRIVATE_KEY_PEM = "-----BEGIN PRIVATE KEY-----\n" + PRIVATE_KEY_PKCS8 + "\n-----END PRIVATE KEY-----";
    private static final String PRIVATE_KEY_PEM_BASE64 = Base64.getEncoder().encodeToString(PRIVATE_KEY_PEM.getBytes(StandardCharsets.US_ASCII));
    private static final String PUBLIC_KEY_SPKI = Base64.getEncoder().encodeToString(TEST_KEY_PAIR.getPublic().getEncoded());
    private static final String KEY_ID = "primary";
    private static final String POLICY_VERSION = "2026-09-12.1";
    private static final String POLICY_HASH = "a".repeat(64);
    private static final String EXECUTOR_DID = "did:t3n:protected-executor-test";
    private static final String OPERATOR = "ops-reviewer";
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void v2CapabilityIsEd25519SignedAndBoundToKeyActionPolicyExecutorAndHumanApproval() throws Exception {
        var signer = new RemediationAuthorizationSigner(mapper, PRIVATE_KEY_PKCS8, KEY_ID, 60, () -> EXECUTOR_DID);
        Map<String, String> normalPayload = Map.of(
            "incident_id", "inc-demo-001",
            "reason", "suspected compromise",
            "credential_id", "cred-demo-001"
        );
        Instant authorizedAt = Instant.now().minusSeconds(2);
        String token = signer.issue(
            "incident-1", "action-1", "request-1", "decision-1",
            "notify-security", "incident:test", "incident-notification", "Security-A.Example",
            List.of("summary", "incident_id", "severity"), normalPayload, List.of("verified_email"),
            POLICY_VERSION, POLICY_HASH, OPERATOR, authorizedAt
        );

        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(3);
        assertThat(parts[0]).isEqualTo("v2");
        var claims = mapper.readTree(Base64.getUrlDecoder().decode(parts[1]));
        assertThat(claims.get("keyId").asText()).isEqualTo(KEY_ID);
        assertThat(claims.get("incidentId").asText()).isEqualTo("incident-1");
        assertThat(claims.get("decisionId").asText()).isEqualTo("decision-1");
        assertThat(claims.get("approvedHost").asText()).isEqualTo("security-a.example");
        assertThat(claims.get("fieldsHash").asText()).hasSize(64);
        assertThat(claims.get("normalPayloadHash").asText()).isEqualTo(NormalPayloadCanonicalizer.sha256(normalPayload));
        assertThat(claims.get("privateRefsHash").asText()).hasSize(64);
        assertThat(claims.get("policyVersion").asText()).isEqualTo(POLICY_VERSION);
        assertThat(claims.get("policyHash").asText()).isEqualTo(POLICY_HASH);
        assertThat(claims.get("executorDid").asText()).isEqualTo(EXECUTOR_DID);
        assertThat(claims.get("operatorPrincipalHash").asText()).isEqualTo(RemediationAuthorizationSigner.operatorPrincipalHash(OPERATOR));
        assertThat(claims.get("authorizedAt").asLong()).isEqualTo(authorizedAt.toEpochMilli());
        assertThat(claims.get("issuedAt").asLong()).isGreaterThanOrEqualTo(claims.get("authorizedAt").asLong());
        assertThat(claims.get("expiresAt").asLong()).isGreaterThan(claims.get("issuedAt").asLong());
        assertThat(claims.get("nonce").asText()).isNotBlank();

        var publicKey = KeyFactory.getInstance("Ed25519")
            .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY_SPKI)));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertThat(verifier.verify(Base64.getUrlDecoder().decode(parts[2]))).isTrue();
    }

    @Test
    void acceptsPkcs8PemBase64WrappedPemAndMatchingBinaryKeyBundle() {
        new RemediationAuthorizationSigner(mapper, PRIVATE_KEY_PEM, KEY_ID, 60, () -> EXECUTOR_DID);
        new RemediationAuthorizationSigner(mapper, PRIVATE_KEY_PEM_BASE64, KEY_ID, 60, () -> EXECUTOR_DID);
        new RemediationAuthorizationSigner(mapper, binaryKeyBundle(PRIVATE_KEY_PKCS8, PUBLIC_KEY_SPKI), KEY_ID, 60, () -> EXECUTOR_DID);
    }

    @Test
    void rejectsBinaryKeyBundleWithMismatchedPublicKey() {
        String otherPublicKey = Base64.getEncoder().encodeToString(generateKeyPair().getPublic().getEncoded());

        assertThatThrownBy(() -> new RemediationAuthorizationSigner(
            mapper,
            binaryKeyBundle(PRIVATE_KEY_PKCS8, otherPublicKey),
            KEY_ID,
            60,
            () -> EXECUTOR_DID
        )).isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("does not match the private key");
    }

    @Test
    void rejectsPkcs8DerWithArbitraryTrailingBinaryData() {
        byte[] privateKey = Base64.getDecoder().decode(PRIVATE_KEY_PKCS8);
        byte[] invalid = Arrays.copyOf(privateKey, privateKey.length + 3);
        invalid[privateKey.length] = 0x01;
        invalid[privateKey.length + 1] = 0x02;
        invalid[privateKey.length + 2] = 0x03;
        String encoded = Base64.getEncoder().encodeToString(invalid);

        assertThatThrownBy(() -> new RemediationAuthorizationSigner(mapper, encoded, KEY_ID, 60, () -> EXECUTOR_DID))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("base64 PKCS#8 Ed25519 private key");
    }

    @Test
    void rejectsPkcs8PemWithTrailingData() {
        assertThatThrownBy(() -> new RemediationAuthorizationSigner(
            mapper,
            PRIVATE_KEY_PEM + "\nunexpected",
            KEY_ID,
            60,
            () -> EXECUTOR_DID
        )).isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("base64 PKCS#8 Ed25519 private key");
    }

    @Test
    void rejectsMissingOrFutureHumanAuthorizationProvenance() {
        var signer = new RemediationAuthorizationSigner(mapper, PRIVATE_KEY_PKCS8, KEY_ID, 60, () -> EXECUTOR_DID);
        Map<String, String> normalPayload = Map.of("incident_id", "inc", "credential_id", "cred", "reason", "test");

        assertThatThrownBy(() -> signer.issue(
            "incident-1", "action-1", "request-1", "decision-1", "revoke-credential", "credential:test", "incident-remediation",
            "postman-echo.com", List.of("incident_id", "credential_id", "reason"), normalPayload, List.of(), POLICY_VERSION, POLICY_HASH, " ", Instant.now()
        )).isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> signer.issue(
            "incident-1", "action-1", "request-1", "decision-1", "revoke-credential", "credential:test", "incident-remediation",
            "postman-echo.com", List.of("incident_id", "credential_id", "reason"), normalPayload, List.of(), POLICY_VERSION, POLICY_HASH, OPERATOR, Instant.now().plusSeconds(30)
        )).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("cannot be after capability issuance");
    }

    @Test
    void rejectsLegacyHmacStyleSecretAndInvalidKeyId() {
        assertThatThrownBy(() -> new RemediationAuthorizationSigner(mapper, "legacy-hmac-secret-that-is-long-enough-123", KEY_ID, 60, () -> EXECUTOR_DID))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("base64 PKCS#8 Ed25519 private key");
        assertThatThrownBy(() -> new RemediationAuthorizationSigner(mapper, PRIVATE_KEY_PKCS8, "../../bad", 60, () -> EXECUTOR_DID))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("REMEDIATION_AUTH_KEY_ID");
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

    private static KeyPair generateKeyPair() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to generate Ed25519 test key pair", ex);
        }
    }

    private static String binaryKeyBundle(String privateKeyPkcs8, String publicKeySpki) {
        byte[] privateKey = Base64.getDecoder().decode(privateKeyPkcs8);
        byte[] publicKey = Base64.getDecoder().decode(publicKeySpki);
        byte[] bundle = Arrays.copyOf(privateKey, privateKey.length + publicKey.length);
        System.arraycopy(publicKey, 0, bundle, privateKey.length, publicKey.length);
        return Base64.getEncoder().encodeToString(bundle);
    }
}
