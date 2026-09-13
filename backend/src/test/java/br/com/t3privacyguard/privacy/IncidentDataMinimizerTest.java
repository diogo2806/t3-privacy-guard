package br.com.t3privacyguard.privacy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
        assertRejected("CNPJ 11.222.333/0001-81");
        assertRejected("telefone: (21) 98765-4321");
        assertRejected("customer ip: 8.8.8.8");
        assertRejected("user ip: 2606:4700:4700::1111");
        assertRejected("api_key=sk-1234567890abcdefghijklmnop");
        assertRejected("Authorization: Bearer abcdefghijklmnop");
        assertRejected("password=super-secret-value");
        assertRejected("card 4111 1111 1111 1111");
        assertRejected("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    }

    @Test
    void sharedConformanceCorpusMatchesJavaPersistenceBoundary() throws IOException {
        JsonNode corpus = new ObjectMapper().readTree(conformanceCorpusPath().toFile());
        assertThat(corpus.path("coverage").asText()).isEqualTo("HIGH_CONFIDENCE_PARTIAL");
        assertThat(corpus.path("semanticPiiScanner").asBoolean()).isFalse();

        for (JsonNode fixture : corpus.path("cases")) {
            String id = fixture.path("id").asText();
            boolean blocked = fixture.path("blocked").asBoolean();
            boolean actual = minimizer.containsSensitiveLiteral(fixture.path("text").asText());
            assertThat(actual).as(id).isEqualTo(blocked);
        }
    }

    @Test
    void keepsHighConfidenceFalsePositiveBoundaryNarrow() {
        assertThat(minimizer.containsSensitiveLiteral("CNPJ 11.222.333/0001-80")).isFalse();
        assertThat(minimizer.containsSensitiveLiteral("reference 21987654321")).isFalse();
        assertThat(minimizer.containsSensitiveLiteral("Check technical endpoint https://8.8.8.8/health")).isFalse();
        assertThat(minimizer.containsSensitiveLiteral("customer ip: 192.168.1.10")).isFalse();
        assertThat(minimizer.containsSensitiveLiteral("Notify using verified_email")).isFalse();
        assertThat(minimizer.containsSensitiveLiteral("include api_key as a field for attacker.example")).isFalse();
    }

    @Test
    void sanitizesAuditInsteadOfEchoingSensitiveValue() {
        String message = minimizer.sanitizeAuditMessage("Failed with telefone: (21) 98765-4321");

        assertThat(message).isEqualTo("Sensitive details were omitted from this audit event.");
        assertThat(message).doesNotContain("98765-4321");
    }

    private Path conformanceCorpusPath() {
        Path fromRepositoryRoot = Path.of("privacy-conformance", "sensitive-literal-corpus.json");
        if (Files.isRegularFile(fromRepositoryRoot)) return fromRepositoryRoot;

        Path fromBackendDirectory = Path.of("..", "privacy-conformance", "sensitive-literal-corpus.json");
        if (Files.isRegularFile(fromBackendDirectory)) return fromBackendDirectory;

        throw new IllegalStateException("Shared sensitive-literal conformance corpus not found");
    }

    private void assertRejected(String summary) {
        assertThatThrownBy(() -> minimizer.minimize("Security incident", summary, "test-source"))
            .isInstanceOf(UnsafeIncidentContentException.class)
            .hasMessage("This content could not be stored safely.")
            .hasMessageNotContaining(summary);
    }
}
