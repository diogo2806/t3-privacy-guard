package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class IncidentIntakeCredentialRegistryTest {
    private static final String TOKEN_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String TOKEN_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    @TempDir Path tempDir;

    @Test
    void runtimeCredentialFileCanRevokeAndRotateWithoutRestart() throws Exception {
        Path credentialsFile = tempDir.resolve("incident-intake.json");
        Files.writeString(credentialsFile, credentialsJson("security-automation", "Security automation", TOKEN_A), StandardCharsets.UTF_8);

        var registry = new IncidentIntakeCredentialRegistry(true, "[]", credentialsFile.toString(), new ObjectMapper());
        assertThat(registry.authenticate(TOKEN_A)).get().extracting(IncidentIntakePrincipal::integrationId).isEqualTo("security-automation");

        Files.writeString(credentialsFile, credentialsJson("secondary-siem", "Secondary SIEM", TOKEN_B), StandardCharsets.UTF_8);

        assertThat(registry.authenticate(TOKEN_A)).isEmpty();
        assertThat(registry.authenticate(TOKEN_B)).get().extracting(IncidentIntakePrincipal::integrationId).isEqualTo("secondary-siem");
    }

    @Test
    void missingOrInvalidRuntimeCredentialFileFailsClosedAfterStartup() throws Exception {
        Path credentialsFile = tempDir.resolve("incident-intake.json");
        Files.writeString(credentialsFile, credentialsJson("security-automation", "Security automation", TOKEN_A), StandardCharsets.UTF_8);
        var registry = new IncidentIntakeCredentialRegistry(true, "[]", credentialsFile.toString(), new ObjectMapper());

        Files.delete(credentialsFile);
        assertThat(registry.authenticate(TOKEN_A)).isEmpty();

        Files.writeString(credentialsFile, "not-json", StandardCharsets.UTF_8);
        assertThat(registry.authenticate(TOKEN_A)).isEmpty();
    }

    private static String credentialsJson(String id, String name, String token) {
        return "[{\"id\":\"" + id + "\",\"name\":\"" + name + "\",\"token\":\"" + token + "\"}]";
    }
}
