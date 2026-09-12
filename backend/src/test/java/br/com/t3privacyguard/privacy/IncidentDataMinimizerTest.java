package br.com.t3privacyguard.privacy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class IncidentDataMinimizerTest {
    private final IncidentDataMinimizer minimizer = new IncidentDataMinimizer();

    @Test
    void normalizesAndCapsAcceptedOperationalText() {
        var result = minimizer.minimize(
            "  Credential   incident  ",
            "A".repeat(1200),
            "  SOC   automation  "
        );

        assertThat(result.title()).isEqualTo("Credential incident");
        assertThat(result.summary()).hasSize(IncidentDataMinimizer.MAX_SUMMARY_LENGTH);
        assertThat(result.source()).isEqualTo("SOC automation");
    }

    @Test
    void rejectsHighConfidenceSensitiveLiteralsBeforePersistence() {
        assertRejected("Contact analyst@example.com immediately");
        assertRejected("CPF 529.982.247-25");
        assertRejected("api_key=sk-1234567890abcdefghijklmnop");
        assertRejected("Authorization: Bearer abcdefghijklmnop");
        assertRejected("password=super-secret-value");
        assertRejected("card 4111 1111 1111 1111");
        assertRejected("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    }

    @Test
    void sanitizesAuditInsteadOfEchoingSensitiveValue() {
        String message = minimizer.sanitizeAuditMessage("Failed with token=abcdefgh12345678");

        assertThat(message).isEqualTo("Sensitive details were omitted from this audit event.");
        assertThat(message).doesNotContain("abcdefgh12345678");
    }

    private void assertRejected(String summary) {
        assertThatThrownBy(() -> minimizer.minimize("Security incident", summary, "test-source"))
            .isInstanceOf(UnsafeIncidentContentException.class)
            .hasMessage("This content could not be stored safely.");
    }
}
