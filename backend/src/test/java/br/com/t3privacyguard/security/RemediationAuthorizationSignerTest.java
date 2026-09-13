package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class RemediationAuthorizationSignerTest {
    private static final String KEY = "test-remediation-capability-key-1234567890";
    private static final String POLICY_VERSION = "2026-09-12.1";
    private static final String POLICY_HASH = "a".repeat(64);
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void capabilityIsSignedAndBoundToActionPrivateReferencesAndPolicyProvenance() throws Exception {
        var signer = new RemediationAuthorizationSigner(mapper, KEY, 60);
        String token = signer.issue(
            "incident-1", "action-1", "request-1", "decision-1",
            "notify-security", "incident:test", "incident-notification",
            List.of("summary", "incident_id", "severity"), List.of("verified_email"),
            POLICY_VERSION, POLICY_HASH
        );

        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(2);
        var claims = mapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
        assertThat(claims.get("incidentId").asText()).isEqualTo("incident-1");
        assertThat(claims.get("decisionId").asText()).isEqualTo("decision-1");
        assertThat(claims.get("fieldsHash").asText()).hasSize(64);
        assertThat(claims.get("privateRefsHash").asText()).hasSize(64);
        assertThat(claims.get("policyVersion").asText()).isEqualTo(POLICY_VERSION);
        assertThat(claims.get("policyHash").asText()).isEqualTo(POLICY_HASH);
        assertThat(claims.get("nonce").asText()).isNotBlank();
        assertThat(claims.get("expiresAt").asLong()).isGreaterThan(claims.get("authorizedAt").asLong());

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String expected = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(mac.doFinal(parts[0].getBytes(StandardCharsets.US_ASCII)));
        assertThat(parts[1]).isEqualTo(expected);
    }
}
