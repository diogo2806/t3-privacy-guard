package br.com.t3privacyguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class EvidenceService {
    private final ObjectMapper mapper;
    private final Path manifestPath;
    private final Path testnetPath;

    public EvidenceService(
        ObjectMapper mapper,
        @Value("${privacy-guard.evidence.manifest-path:../docs/evidence/deployment-manifest.json}") String manifestPath,
        @Value("${privacy-guard.evidence.testnet-path:../docs/evidence/testnet-run.json}") String testnetPath
    ) {
        this.mapper = mapper;
        this.manifestPath = Path.of(manifestPath).normalize();
        this.testnetPath = Path.of(testnetPath).normalize();
    }

    public EvidenceResponse latest() {
        if (!Files.isRegularFile(manifestPath) || !Files.isRegularFile(testnetPath)) {
            throw new EvidenceNotFoundException("No live T3N evidence has been generated yet.");
        }
        try {
            JsonNode manifest = mapper.readTree(Files.readString(manifestPath));
            JsonNode testnet = mapper.readTree(Files.readString(testnetPath));
            String source = required(manifest, "source");
            if (!"T3N_TESTNET".equals(source)) throw new IllegalStateException("Evidence source is not T3N_TESTNET");

            Metadata metadata = new Metadata(
                source,
                required(manifest, "generatedAt"),
                required(manifest, "network"),
                required(manifest, "sdkVersion"),
                required(manifest, "tenantDid"),
                required(manifest, "agentDid"),
                required(manifest, "contractId"),
                required(manifest, "contractVersion"),
                required(manifest, "wasmSha256"),
                required(manifest, "policyVersion"),
                required(manifest, "policyHash"),
                requiredBoolean(manifest, "trustAnchorVerified"),
                requiredBoolean(manifest, "trustManifestFloorPersisted"),
                requiredPositiveLong(manifest, "trustManifestVersion")
            );
            validateMetadata(metadata);
            assertSame(testnet, "network", metadata.network());
            assertSame(testnet, "sdkVersion", metadata.sdkVersion());
            assertSame(testnet, "tenantDid", metadata.tenantDid());
            assertSame(testnet, "agentDid", metadata.agentDid());
            assertSame(testnet, "contractId", metadata.contractId());
            assertSame(testnet, "contractVersion", metadata.contractVersion());
            assertSame(testnet, "wasmSha256", metadata.wasmSha256());
            assertSame(testnet, "policyVersion", metadata.policyVersion());
            assertSame(testnet, "policyHash", metadata.policyHash());

            JsonNode scenarioNodes = testnet.path("scenarios");
            if (!scenarioNodes.isArray()) throw new IllegalStateException("Evidence scenarios are missing");
            List<Scenario> scenarios = new ArrayList<>();
            int pass = 0;
            int fail = 0;
            int notRun = 0;
            for (JsonNode node : scenarioNodes) {
                String status = required(node, "status");
                if (!List.of("PASS", "FAIL", "NOT_RUN").contains(status)) throw new IllegalStateException("Unknown evidence scenario status");
                Scenario scenario = new Scenario(
                    required(node, "id"),
                    required(node, "expected"),
                    nullableText(node, "actual"),
                    status,
                    nullableText(node, "detail")
                );
                scenarios.add(scenario);
                if ("PASS".equals(status)) pass++;
                else if ("FAIL".equals(status)) fail++;
                else notRun++;
            }
            return new EvidenceResponse(metadata, scenarios, new Totals(pass, fail, notRun));
        } catch (IOException | RuntimeException ex) {
            if (ex instanceof EvidenceNotFoundException) throw ex;
            throw new IllegalStateException("Live evidence is present but invalid or inconsistent", ex);
        }
    }

    private static void validateMetadata(Metadata value) {
        if (!value.tenantDid().startsWith("did:t3n:") || !value.agentDid().startsWith("did:t3n:")) throw new IllegalStateException("Evidence DIDs are invalid");
        if (value.tenantDid().equals(value.agentDid())) throw new IllegalStateException("Evidence tenant and agent DIDs must differ");
        if (!value.wasmSha256().matches("[a-f0-9]{64}")) throw new IllegalStateException("Evidence WASM SHA-256 is invalid");
        if (value.policyVersion().isBlank() || !value.policyHash().matches("[a-f0-9]{64}")) throw new IllegalStateException("Evidence policy provenance is invalid");
        if (!value.trustAnchorVerified()) throw new IllegalStateException("Evidence trust anchor is not verified");
        if (!value.trustManifestFloorPersisted()) throw new IllegalStateException("Evidence trust manifest rollback floor is not persisted");
        if (value.trustManifestVersion() < 1) throw new IllegalStateException("Evidence trust manifest version is invalid");
    }

    private static String required(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isTextual() || value.asText().isBlank()) throw new IllegalStateException("Missing evidence field: " + field);
        return value.asText();
    }

    private static boolean requiredBoolean(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isBoolean()) throw new IllegalStateException("Missing evidence boolean field: " + field);
        return value.booleanValue();
    }

    private static long requiredPositiveLong(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.canConvertToLong() || !value.isIntegralNumber() || value.longValue() < 1) {
            throw new IllegalStateException("Missing or invalid evidence integer field: " + field);
        }
        return value.longValue();
    }

    private static String nullableText(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static void assertSame(JsonNode node, String field, String expected) {
        if (!expected.equals(required(node, field))) throw new IllegalStateException("Evidence mismatch for " + field);
    }

    public record EvidenceResponse(Metadata metadata, List<Scenario> scenarios, Totals totals) {}
    public record Metadata(
        String source,
        String generatedAt,
        String network,
        String sdkVersion,
        String tenantDid,
        String agentDid,
        String contractId,
        String contractVersion,
        String wasmSha256,
        String policyVersion,
        String policyHash,
        boolean trustAnchorVerified,
        boolean trustManifestFloorPersisted,
        long trustManifestVersion
    ) {}
    public record Scenario(String id, String expected, String actual, String status, String detail) {}
    public record Totals(int pass, int fail, int notRun) {}
}
