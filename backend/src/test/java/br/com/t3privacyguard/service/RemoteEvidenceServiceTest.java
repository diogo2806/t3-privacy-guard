package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.EvidenceBundle;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class RemoteEvidenceServiceTest {
    private static final String SHA = "a".repeat(40);
    private static final String WASM = "b".repeat(64);
    private static final String POLICY = "c".repeat(64);
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void readsValidatedEvidenceFromAuthenticatedGatewayInsteadOfLocalFilesystem() throws Exception {
        GatewaySystemClient gateway = mock(GatewaySystemClient.class);
        when(gateway.evidenceBundle()).thenReturn(new EvidenceBundle("AVAILABLE", manifest(), testnet()));
        EvidenceService service = new EvidenceService(mapper, gateway, "/does/not/exist/manifest.json", "/does/not/exist/testnet.json");

        var state = service.latestState();

        assertThat(state.available()).isTrue();
        assertThat(state.evidence().metadata().sourceCommitSha()).isEqualTo(SHA);
        assertThat(state.evidence().metadata().tenantDid()).isEqualTo("did:t3n:tenant");
        assertThat(state.evidence().totals().pass()).isZero();
    }

    @Test
    void gatewayAbsenceDoesNotFallBackToPotentiallyStaleLocalFiles() {
        GatewaySystemClient gateway = mock(GatewaySystemClient.class);
        when(gateway.evidenceBundle()).thenReturn(new EvidenceBundle("ABSENT", null, null));
        EvidenceService service = new EvidenceService(mapper, gateway, "../docs/evidence/deployment-manifest.json", "../docs/evidence/testnet-run.json");

        assertThat(service.latestState().available()).isFalse();
    }

    @Test
    void invalidGatewayBundleFailsClosed() {
        GatewaySystemClient gateway = mock(GatewaySystemClient.class);
        when(gateway.evidenceBundle()).thenReturn(new EvidenceBundle("INVALID", null, null));
        EvidenceService service = new EvidenceService(mapper, gateway, "/missing/manifest", "/missing/run");

        assertThatThrownBy(service::latestState)
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("gateway");
    }

    private JsonNode manifest() throws Exception {
        return mapper.readTree("""
            {
              "source":"T3N_TESTNET",
              "generatedAt":"2026-09-16T16:00:00Z",
              "sourceCommitSha":"%s",
              "sourceTreeClean":true,
              "network":"testnet",
              "sdkVersion":"5.2.0",
              "tenantDid":"did:t3n:tenant",
              "agentDid":"did:t3n:agent",
              "executorDid":"did:t3n:executor",
              "agentRegistrationState":"NOT_REGISTERED",
              "agentCardUri":null,
              "agentCardSha256":null,
              "agentCardVerifiedAt":"2026-09-16T16:00:00Z",
              "agentCardServices":[],
              "contractId":"z:tenant:privacy-guard",
              "contractVersion":"0.4.0",
              "wasmSha256":"%s",
              "policyVersion":"2026-09-16.1",
              "policyHash":"%s",
              "trustAnchorVerified":true,
              "trustManifestFloorPersisted":true,
              "trustManifestVersion":1
            }
            """.formatted(SHA, WASM, POLICY));
    }

    private JsonNode testnet() throws Exception {
        return mapper.readTree("""
            {
              "sourceCommitSha":"%s",
              "sourceTreeClean":true,
              "network":"testnet",
              "sdkVersion":"5.2.0",
              "tenantDid":"did:t3n:tenant",
              "agentDid":"did:t3n:agent",
              "executorDid":"did:t3n:executor",
              "contractId":"z:tenant:privacy-guard",
              "contractVersion":"0.4.0",
              "wasmSha256":"%s",
              "policyVersion":"2026-09-16.1",
              "policyHash":"%s",
              "scenarios":[]
            }
            """.formatted(SHA, WASM, POLICY));
    }
}
