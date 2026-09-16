package br.com.t3privacyguard.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class EvidenceService {
    private static final List<String> REGISTRATION_STATES = List.of("REGISTERED", "NOT_REGISTERED", "MISMATCH", "UNAVAILABLE");
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

    public EvidenceAvailability latestState() {
        boolean manifestAvailable = Files.isRegularFile(manifestPath);
        boolean testnetAvailable = Files.isRegularFile(testnetPath);
        if (!manifestAvailable && !testnetAvailable) {
            return new EvidenceAvailability(false, null);
        }
        if (manifestAvailable != testnetAvailable) {
            throw new IllegalStateException("Live evidence bundle is incomplete");
        }
        return new EvidenceAvailability(true, latest());
    }

    public EvidenceResponse latest() {
        boolean manifestAvailable = Files.isRegularFile(manifestPath);
        boolean testnetAvailable = Files.isRegularFile(testnetPath);
        if (!manifestAvailable && !testnetAvailable) {
            throw new EvidenceNotFoundException("No live T3N evidence has been generated yet.");
        }
        if (manifestAvailable != testnetAvailable) {
            throw new IllegalStateException("Live evidence bundle is incomplete");
        }
        try {
            JsonNode manifest = mapper.readTree(Files.readString(manifestPath));
            JsonNode testnet = mapper.readTree(Files.readString(testnetPath));
            String source = required(manifest, "source");
            if (!"T3N_TESTNET".equals(source)) throw new IllegalStateException("Evidence source is not T3N_TESTNET");

            Metadata metadata = new Metadata(
                source,
                required(manifest, "generatedAt"),
                required(manifest, "sourceCommitSha"),
                requiredBoolean(manifest, "sourceTreeClean"),
                required(manifest, "network"),
                required(manifest, "sdkVersion"),
                required(manifest, "tenantDid"),
                required(manifest, "agentDid"),
                required(manifest, "executorDid"),
                required(manifest, "agentRegistrationState"),
                nullableText(manifest, "agentCardUri"),
                nullableText(manifest, "agentCardSha256"),
                required(manifest, "agentCardVerifiedAt"),
                textArray(manifest, "agentCardServices"),
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
            assertSame(testnet, "sourceCommitSha", metadata.sourceCommitSha());
            assertSameBoolean(testnet, "sourceTreeClean", metadata.sourceTreeClean());
            assertSame(testnet, "network", metadata.network());
            assertSame(testnet, "sdkVersion", metadata.sdkVersion());
            assertSame(testnet, "tenantDid", metadata.tenantDid());
            assertSame(testnet, "agentDid", metadata.agentDid());
            assertSame(testnet, "executorDid", metadata.executorDid());
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
            if (ex instanceof EvidenceNotFoundException notFound) throw notFound;
            throw new IllegalStateException("Live evidence is present but invalid or inconsistent", ex);
        }
    }

    private static void validateMetadata(Metadata value) {
        if (!value.sourceCommitSha().matches("[a-f0-9]{40}")) throw new IllegalStateException("Evidence source commit SHA is invalid");
        if (!value.tenantDid().startsWith("did:t3n:") || !value.agentDid().startsWith("did:t3n:") || !value.executorDid().startsWith("did:t3n:")) {
            throw new IllegalStateException("Evidence DIDs are invalid");
        }
        if (new HashSet<>(List.of(value.tenantDid(), value.agentDid(), value.executorDid())).size() != 3) {
            throw new IllegalStateException("Evidence tenant, proposal agent and protected executor DIDs must differ");
        }
        if (!value.wasmSha256().matches("[a-f0-9]{64}")) throw new IllegalStateException("Evidence WASM SHA-256 is invalid");
        if (value.policyVersion().isBlank() || !value.policyHash().matches("[a-f0-9]{64}")) throw new IllegalStateException("Evidence policy provenance is invalid");
        if (!REGISTRATION_STATES.contains(value.agentRegistrationState())) throw new IllegalStateException("Evidence Agent registration state is invalid");
        try { Instant.parse(value.agentCardVerifiedAt()); } catch (RuntimeException ex) { throw new IllegalStateException("Evidence Agent Card verification timestamp is invalid", ex); }
        if ("REGISTERED".equals(value.agentRegistrationState())) {
            if (value.agentCardUri() == null || !"https".equalsIgnoreCase(URI.create(value.agentCardUri()).getScheme())) throw new IllegalStateException("Registered Agent evidence requires an HTTPS card URI");
            if (value.agentCardSha256() == null || !value.agentCardSha256().matches("[a-f0-9]{64}")) throw new IllegalStateException("Registered Agent evidence requires a valid card SHA-256");
            if (!value.agentCardServices().equals(List.of("DID"))) throw new IllegalStateException("Registered Agent evidence must advertise only the DID service");
        }
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

    private static List<String> textArray(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || !value.isArray()) throw new IllegalStateException("Missing evidence array: " + field);
        List<String> result = new ArrayList<>();
        for (JsonNode item : value) {
            if (!item.isTextual() || item.asText().isBlank()) throw new IllegalStateException("Invalid evidence array value: " + field);
            result.add(item.asText());
        }
        return List.copyOf(result);
    }

    private static void assertSame(JsonNode node, String field, String expected) {
        if (!expected.equals(required(node, field))) throw new IllegalStateException("Evidence mismatch for " + field);
    }

    private static void assertSameBoolean(JsonNode node, String field, boolean expected) {
        if (requiredBoolean(node, field) != expected) throw new IllegalStateException("Evidence mismatch for " + field);
    }

    public record EvidenceAvailability(boolean available, EvidenceResponse evidence) {}
    public record EvidenceResponse(Metadata metadata, List<Scenario> scenarios, Totals totals) {}
    public record Metadata(
        String source,
        String generatedAt,
        String sourceCommitSha,
        boolean sourceTreeClean,
        String network,
        String sdkVersion,
        String tenantDid,
        String agentDid,
        String executorDid,
        String agentRegistrationState,
        String agentCardUri,
        String agentCardSha256,
        String agentCardVerifiedAt,
        List<String> agentCardServices,
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
