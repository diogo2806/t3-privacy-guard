package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EvidenceServiceTest {
    @TempDir Path tempDir;
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void readsAllowlistedPolicyTrustAgentAndExecutorEvidence() throws Exception {
        Path manifest = tempDir.resolve("deployment-manifest.json");
        Path testnet = tempDir.resolve("testnet-run.json");
        String wasmHash = "a".repeat(64);
        String policyHash = "b".repeat(64);
        Map<String, Object> manifestData = validManifest(wasmHash, "2026-09-12.1", policyHash);
        manifestData.put("unexpectedSecretField", "must-not-cross");
        write(manifest, manifestData);
        write(testnet, validRun(wasmHash, "2026-09-12.1", policyHash, List.of(
            Map.of("id", "s1", "expected", "DENY", "actual", "DENY", "status", "PASS"),
            Map.of("id", "s2", "expected", "blocked", "status", "NOT_RUN")
        )));

        var result = new EvidenceService(mapper, manifest.toString(), testnet.toString()).latest();
        assertThat(result.metadata().source()).isEqualTo("T3N_TESTNET");
        assertThat(result.metadata().policyVersion()).isEqualTo("2026-09-12.1");
        assertThat(result.metadata().policyHash()).isEqualTo(policyHash);
        assertThat(result.metadata().agentDid()).isEqualTo("did:t3n:proposal-agent");
        assertThat(result.metadata().executorDid()).isEqualTo("did:t3n:protected-executor");
        assertThat(result.metadata().agentRegistrationState()).isEqualTo("REGISTERED");
        assertThat(result.metadata().agentCardUri()).startsWith("https://");
        assertThat(result.metadata().agentCardSha256()).hasSize(64);
        assertThat(result.metadata().agentCardServices()).containsExactly("DID");
        assertThat(result.metadata().trustAnchorVerified()).isTrue();
        assertThat(result.metadata().trustManifestFloorPersisted()).isTrue();
        assertThat(result.totals().pass()).isEqualTo(1);
        assertThat(result.totals().notRun()).isEqualTo(1);
        assertThat(mapper.writeValueAsString(result)).doesNotContain("must-not-cross");
    }

    @Test
    void missingLiveEvidenceIsExplicitlyNotFound() {
        var service = new EvidenceService(mapper, tempDir.resolve("missing-manifest.json").toString(), tempDir.resolve("missing-run.json").toString());
        assertThatThrownBy(service::latest).isInstanceOf(EvidenceNotFoundException.class);
    }

    @Test
    void reusedProposalAndExecutorDidFailsClosed() throws Exception {
        Path manifest = tempDir.resolve("manifest-duplicate-did.json");
        Path testnet = tempDir.resolve("run-duplicate-did.json");
        String wasmHash = "9".repeat(64);
        String policyHash = "8".repeat(64);
        Map<String, Object> invalid = validManifest(wasmHash, "2026-09-12.1", policyHash);
        invalid.put("executorDid", "did:t3n:proposal-agent");
        write(manifest, invalid);
        Map<String, Object> run = validRun(wasmHash, "2026-09-12.1", policyHash, List.of());
        run.put("executorDid", "did:t3n:proposal-agent");
        write(testnet, run);
        assertThatThrownBy(() -> new EvidenceService(mapper, manifest.toString(), testnet.toString()).latest())
            .isInstanceOf(IllegalStateException.class).hasMessageContaining("invalid or inconsistent");
    }

    @Test
    void registeredAgentWithoutHttpsCardOrHashFailsClosed() throws Exception {
        Path manifest = tempDir.resolve("manifest-card.json");
        Path testnet = tempDir.resolve("run-card.json");
        String wasmHash = "c".repeat(64);
        String policyHash = "d".repeat(64);
        Map<String, Object> invalid = validManifest(wasmHash, "2026-09-12.1", policyHash);
        invalid.put("agentCardUri", "http://internal/card");
        invalid.put("agentCardSha256", null);
        write(manifest, invalid);
        write(testnet, validRun(wasmHash, "2026-09-12.1", policyHash, List.of()));
        assertThatThrownBy(() -> new EvidenceService(mapper, manifest.toString(), testnet.toString()).latest())
            .isInstanceOf(IllegalStateException.class).hasMessageContaining("invalid or inconsistent");
    }

    @Test
    void policyOrContractIdentityMismatchFailsClosed() throws Exception {
        Path manifest = tempDir.resolve("manifest-policy.json");
        Path testnet = tempDir.resolve("run-policy.json");
        String wasmHash = "e".repeat(64);
        write(manifest, validManifest(wasmHash, "2026-09-12.1", "f".repeat(64)));
        write(testnet, validRun(wasmHash, "2026-09-12.2", "0".repeat(64), List.of()));
        assertThatThrownBy(() -> new EvidenceService(mapper, manifest.toString(), testnet.toString()).latest())
            .isInstanceOf(IllegalStateException.class).hasMessageContaining("invalid or inconsistent");
    }

    @Test
    void unverifiedTrustMetadataFailsClosed() throws Exception {
        Path manifest = tempDir.resolve("manifest-trust.json");
        Path testnet = tempDir.resolve("run-trust.json");
        String wasmHash = "1".repeat(64);
        String policyHash = "2".repeat(64);
        Map<String, Object> invalid = validManifest(wasmHash, "2026-09-12.1", policyHash);
        invalid.put("trustAnchorVerified", false);
        write(manifest, invalid);
        write(testnet, validRun(wasmHash, "2026-09-12.1", policyHash, List.of()));
        assertThatThrownBy(() -> new EvidenceService(mapper, manifest.toString(), testnet.toString()).latest())
            .isInstanceOf(IllegalStateException.class).hasMessageContaining("invalid or inconsistent");
    }

    private Map<String, Object> validManifest(String wasmHash, String policyVersion, String policyHash) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("source", "T3N_TESTNET"); value.put("generatedAt", "2026-09-12T00:00:00Z"); value.put("network", "testnet"); value.put("sdkVersion", "5.2.0");
        value.put("tenantDid", "did:t3n:tenant"); value.put("agentDid", "did:t3n:proposal-agent"); value.put("executorDid", "did:t3n:protected-executor");
        value.put("agentRegistrationState", "REGISTERED"); value.put("agentCardUri", "https://node.example/agent-card/did:t3n:proposal-agent");
        value.put("agentCardSha256", "3".repeat(64)); value.put("agentCardVerifiedAt", "2026-09-12T00:00:01Z"); value.put("agentCardServices", List.of("DID"));
        value.put("contractId", "z:tenant:privacy-guard"); value.put("contractVersion", "0.4.0"); value.put("wasmSha256", wasmHash);
        value.put("policyVersion", policyVersion); value.put("policyHash", policyHash);
        value.put("trustAnchorVerified", true); value.put("trustManifestFloorPersisted", true); value.put("trustManifestVersion", 42);
        return value;
    }

    private Map<String, Object> validRun(String wasmHash, String policyVersion, String policyHash, List<Map<String, Object>> scenarios) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("network", "testnet"); value.put("sdkVersion", "5.2.0"); value.put("tenantDid", "did:t3n:tenant"); value.put("agentDid", "did:t3n:proposal-agent"); value.put("executorDid", "did:t3n:protected-executor");
        value.put("contractId", "z:tenant:privacy-guard"); value.put("contractVersion", "0.4.0"); value.put("wasmSha256", wasmHash);
        value.put("policyVersion", policyVersion); value.put("policyHash", policyHash); value.put("scenarios", scenarios);
        return value;
    }

    private void write(Path path, Object value) throws Exception { Files.writeString(path, mapper.writeValueAsString(value)); }
}
