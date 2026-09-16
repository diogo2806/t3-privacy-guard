package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EvidenceAvailabilityTest {
    @TempDir Path tempDir;
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void reportsUnavailableWhenNoLiveEvidenceArtifactsExist() {
        var service = service();

        var state = service.latestState();

        assertThat(state.available()).isFalse();
        assertThat(state.evidence()).isNull();
    }

    @Test
    void partialLiveEvidenceBundleFailsClosedInsteadOfLookingUnavailable() throws Exception {
        Files.writeString(tempDir.resolve("deployment-manifest.json"), "{}");
        var service = service();

        assertThatThrownBy(service::latestState)
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("incomplete");
    }

    private EvidenceService service() {
        return new EvidenceService(
            mapper,
            tempDir.resolve("deployment-manifest.json").toString(),
            tempDir.resolve("testnet-run.json").toString()
        );
    }
}
