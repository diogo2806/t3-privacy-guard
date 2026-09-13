package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.audit.AuditIntegrityService;
import br.com.t3privacyguard.audit.AuditIntegrityState;
import br.com.t3privacyguard.domain.AuditReconciliationStatus;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.ActivityEvent;
import br.com.t3privacyguard.integration.GatewaySystemClient.ActivityPage;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuditEvidenceServiceTest {
    private IncidentRepository incidents;
    private AuditIntegrityService integrity;
    private GatewaySystemClient gateway;
    private AuditEvidenceService service;
    private IncidentEntity incident;

    @BeforeEach
    void setUp() {
        incidents = mock(IncidentRepository.class);
        integrity = mock(AuditIntegrityService.class);
        gateway = mock(GatewaySystemClient.class);
        service = new AuditEvidenceService(incidents, integrity, gateway);
        Instant createdAt = Instant.now().minusSeconds(60);
        incident = new IncidentEntity("incident-1", "Test", Severity.HIGH, "Summary", "test", createdAt, createdAt.plusSeconds(3600));
        when(incidents.findById("incident-1")).thenReturn(Optional.of(incident));
    }

    @Test
    void matchesOnlyExactSequenceHashContractAgentAndFunction() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "INCIDENT_CREATED", "Created", Instant.now().minusSeconds(50)),
            new AuditEventEntity("local-2", "incident-1", "POLICY_DECISION", "Allowed", Instant.now().minusSeconds(40), 42L, "hash-42", "evaluate-action"),
            new AuditEventEntity("local-3", "incident-1", "REMEDIATION_ACCEPTED", "Accepted", Instant.now().minusSeconds(30), null, null, "execute-remediation")
        );
        verifiedLocal(local);
        availableIdentity();
        when(gateway.activity(org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.eq(100)))
            .thenReturn(Optional.of(new ActivityPage(List.of(
                activity(43, "hash-43", "execute-remediation", "did:t3n:agent", "z:tenant:privacy-guard"),
                activity(42, "hash-42", "evaluate-action", "did:t3n:agent", "z:tenant:privacy-guard"),
                activity(41, "ignored", "evaluate-action", "did:t3n:other-agent", "z:tenant:privacy-guard"),
                activity(40, "ignored", "evaluate-action", "did:t3n:agent", "z:other:contract")
            ), null, true)));

        var result = service.read("incident-1", 100);

        assertThat(result.integrity().state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(result.localEvents()).extracting(event -> event.status()).containsExactly(
            AuditReconciliationStatus.LOCAL_ONLY,
            AuditReconciliationStatus.MATCHED,
            AuditReconciliationStatus.UNMATCHED
        );
        assertThat(result.localEvents().get(2).matchedSequence()).isNull();
        assertThat(result.t3nEvents()).extracting(event -> event.sequence()).containsExactly(43L, 42L);
        assertThat(result.t3nEvents()).extracting(event -> event.status()).containsExactly(
            AuditReconciliationStatus.T3N_ONLY,
            AuditReconciliationStatus.MATCHED
        );
        assertThat(result.provenance().matched()).isEqualTo(1);
        assertThat(result.provenance().unmatched()).isEqualTo(1);
        assertThat(result.provenance().t3nOnly()).isEqualTo(1);
    }

    @Test
    void hashMismatchIsUnmatchedAndNeverFallsBackToApproximation() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), 42L, "different-hash", "evaluate-action")
        );
        verifiedLocal(local);
        availableIdentity();
        when(gateway.activity(org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.eq(100)))
            .thenReturn(Optional.of(new ActivityPage(List.of(
                activity(42, "hash-42", "evaluate-action", "did:t3n:agent", "z:tenant:privacy-guard")
            ), null, true)));

        var result = service.read("incident-1", 100);

        assertThat(result.localEvents().getFirst().status()).isEqualTo(AuditReconciliationStatus.UNMATCHED);
        assertThat(result.t3nEvents().getFirst().status()).isEqualTo(AuditReconciliationStatus.T3N_ONLY);
        assertThat(result.provenance().matched()).isZero();
    }

    @Test
    void preservesLocalIntegritySignalWhenT3nActivityIsUnavailable() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "INCIDENT_CREATED", "Created", Instant.now()),
            new AuditEventEntity("local-2", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), null, null, "evaluate-action")
        );
        verifiedLocal(local);
        when(gateway.tenantStatus()).thenReturn(Optional.empty());

        var result = service.read("incident-1", 100);

        assertThat(result.integrity().state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(result.localEvents()).hasSize(2);
        assertThat(result.t3nEvents()).isEmpty();
        assertThat(result.provenance().t3nAvailable()).isFalse();
        assertThat(result.provenance().message()).isEqualTo("T3N activity temporarily unavailable. Local business audit remains available; network provenance was not verified.");
    }

    private void verifiedLocal(List<AuditEventEntity> local) {
        when(integrity.verify("incident-1")).thenReturn(new AuditIntegrityService.Verification(
            AuditIntegrityState.VERIFIED,
            local.size(),
            "a".repeat(64),
            "v1",
            "HMAC chain verified.",
            local
        ));
    }

    private void availableIdentity() {
        when(gateway.tenantStatus()).thenReturn(Optional.of(new GatewaySystemClient.TenantStatus(true, true, "did:t3n:tenant", "testnet")));
        when(gateway.agentStatus()).thenReturn(Optional.of(new GatewaySystemClient.AgentStatus(true, true, true, "did:t3n:agent", "testnet")));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new GatewaySystemClient.ContractIdentity("z:tenant:privacy-guard", "1")));
    }

    private static ActivityEvent activity(long sequence, String hash, String function, String actorDid, String contractId) {
        return new ActivityEvent(
            sequence,
            hash,
            Instant.now().toEpochMilli(),
            "agent",
            actorDid,
            "did:t3n:tenant",
            contractId,
            function,
            "success",
            List.of("incident-agent")
        );
    }
}
