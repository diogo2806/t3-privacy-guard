package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EvidenceServiceTest {
    @TempDir Path tempDir;
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void readsOnlyAllowlistedLiveEvidenceFieldsAndCountsStates() throws Exception {
        Path manifest = tempDir.resolve("deployment-manifest.json");
        Path testnet = tempDir.resolve("testnet-run.json");
        String hash = "a".repeat(64);
        Files.writeString(manifest, """
            {"source":"T3N_TESTNET","generatedAt":"2026-09-12T00:00:00Z","network":"testnet","sdkVersion":"5.2.0","tenantDid":"did:t3n:tenant","agentDid":"did:t3n:agent","contractId":"z:tenant:privacy-guard","contractVersion":"0.3.0","wasmSha256":"%s","trustAnchorVerified":true,"trustManifestFloorPersisted":true,"trustManifestVersion":42,"unexpectedSecretField":"must-not-cross"}
            """.formatted(hash));
        Files.writeString(testnet, """
            {"network":"testnet","sdkVersion":"5.2.0","tenantDid":"did:t3n:tenant","agentDid":"did:t3n:agent","contractId":"z:tenant:privacy-guard","contractVersion":"0.3.0","wasmSha256":"%s","scenarios":[{"id":"s1","expected":"DENY","actual":"DENY","status":"PASS"},{"id":"s2","expected":"blocked","actual":null,"status":"NOT_RUN"}]}
            """.formatted(hash));

        var result = new EvidenceService(mapper, manifest.toString(), testnet.toString()).latest();
        assertThat(result.metadata().source()).isEqualTo("T3N_TESTNET");
        assertThat(result.metadata().contractVersion()).isEqualTo("0.3.0");
        assertThat(result.metadata().trustAnchorVerified()).isTrue();
        assertThat(result.metadata().trustManifestFloorPersisted()).isTrue();
        assertThat(result.metadata().trustManifestVersion()).isEqualTo(42);
        assertThat(result.totals().pass()).isEqualTo(1);
        assertThat(result.totals().fail()).isZero();
        assertThat(result.totals().notRun()).isEqualTo(1);
        assertThat(mapper.writeValueAsString(result)).doesNotContain("must-not-cross");
    }

    @Test
    void missingLiveEvidenceIsExplicitlyNotFound() {
        var service = new EvidenceService(mapper, tempDir.resolve("missing-manifest.json").toString(), tempDir.resolve("missing-run.json").toString());
        assertThatThrownBy(service::latest).isInstanceOf(EvidenceNotFoundException.class);
    }

    @Test
    void mismatchedHashFailsInsteadOfPresentingEvidence() throws Exception {
        Path manifest = tempDir.resolve("manifest.json");
        Path testnet = tempDir.resolve("run.json");
        Files.writeString(manifest, "{\"source\":\"T3N_TESTNET\",\"generatedAt\":\"2026-09-12T00:00:00Z\",\"network\":\"testnet\",\"sdkVersion\":\"5.2.0\",\"tenantDid\":\"did:t3n:tenant\",\"agentDid\":\"did:t3n:agent\",\"contractId\":\"z:tenant:privacy-guard\",\"contractVersion\":\"0.3.0\",\"wasmSha256\":\"" + "a".repeat(64) + "\",\"trustAnchorVerified\":true,\"trustManifestFloorPersisted\":true,\"trustManifestVersion\":42}");
        Files.writeString(testnet, "{\"network\":\"testnet\",\"sdkVersion\":\"5.2.0\",\"tenantDid\":\"did:t3n:tenant\",\"agentDid\":\"did:t3n:agent\",\"contractId\":\"z:tenant:privacy-guard\",\"contractVersion\":\"0.3.0\",\"wasmSha256\":\"" + "b".repeat(64) + "\",\"scenarios\":[]}");
        assertThatThrownBy(() -> new EvidenceService(mapper, manifest.toString(), testnet.toString()).latest())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("invalid or inconsistent");
    }

    @Test
    void unverifiedOrMissingTrustMetadataFailsClosed() throws Exception {
        Path manifest = tempDir.resolve("manifest-trust.json");
        Path testnet = tempDir.resolve("run-trust.json");
        String hash = "c".repeat(64);
        Files.writeString(testnet, "{\"network\":\"testnet\",\"sdkVersion\":\"5.2.0\",\"tenantDid\":\"did:t3n:tenant\",\"agentDid\":\"did:t3n:agent\",\"contractId\":\"z:tenant:privacy-guard\",\"contractVersion\":\"0.3.0\",\"wasmSha256\":\"" + hash + "\",\"scenarios\":[]}");

        Files.writeString(manifest, "{\"source\":\"T3N_TESTNET\",\"generatedAt\":\"2026-09-12T00:00:00Z\",\"network\":\"testnet\",\"sdkVersion\":\"5.2.0\",\"tenantDid\":\"did:t3n:tenant\",\"agentDid\":\"did:t3n:agent\",\"contractId\":\"z:tenant:privacy-guard\",\"contractVersion\":\"0.3.0\",\"wasmSha256\":\"" + hash + "\",\"trustAnchorVerified\":false,\"trustManifestFloorPersisted\":true,\"trustManifestVersion\":42}");
        assertThatThrownBy(() -> new EvidenceService(mapper, manifest.toString(), testnet.toString()).latest())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("invalid or inconsistent");

        Files.writeString(manifest, "{\"source\":\"T3N_TESTNET\",\"generatedAt\":\"2026-09-12T00:00:00Z\",\"network\":\"testnet\",\"sdkVersion\":\"5.2.0\",\"tenantDid\":\"did:t3n:tenant\",\"agentDid\":\"did:t3n:agent\",\"contractId\":\"z:tenant:privacy-guard\",\"contractVersion\":\"0.3.0\",\"wasmSha256\":\"" + hash + "\"}");
        assertThatThrownBy(() -> new EvidenceService(mapper, manifest.toString(), testnet.toString()).latest())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("invalid or inconsistent");
    }
}
