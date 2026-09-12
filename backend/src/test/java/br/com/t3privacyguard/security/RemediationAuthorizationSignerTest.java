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
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void capabilityIsSignedAndBoundToAction() throws Exception {
        var signer = new RemediationAuthorizationSigner(mapper, KEY, 60);
        String token = signer.issue(
            "incident-1",
            "action-1",
            "request-1",
            "decision-1",
            "revoke-credential",
            "credential:test",
            "incident-remediation",
            List.of("reason", "incident_id", "credential_id")
        );

        String[] parts = token.split("\\.");
        assertThat(parts).hasSize(2);
        var claims = mapper.readTree(Base64.getUrlDecoder().decode(parts[0]));
        assertThat(claims.get("incidentId").asText()).isEqualTo("incident-1");
        assertThat(claims.get("decisionId").asText()).isEqualTo("decision-1");
        assertThat(claims.get("nonce").asText()).isNotBlank();
        assertThat(claims.get("expiresAt").asLong()).isGreaterThan(claims.get("authorizedAt").asLong());

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(KEY.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String expected = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(mac.doFinal(parts[0].getBytes(StandardCharsets.US_ASCII)));
        assertThat(parts[1]).isEqualTo(expected);
    }
}
