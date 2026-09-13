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
    private AuditIntegrityService auditIntegrity;
    private GatewaySystemClient gateway;
    private AuditEvidenceService service;
    private IncidentEntity incident;

    @BeforeEach
    void setUp() {
        incidents = mock(IncidentRepository.class);
        auditIntegrity = mock(AuditIntegrityService.class);
        gateway = mock(GatewaySystemClient.class);
        service = new AuditEvidenceService(incidents, auditIntegrity, gateway);
        Instant createdAt = Instant.now().minusSeconds(60);
        incident = new IncidentEntity("incident-1", "Test", Severity.HIGH, "Summary", "test", createdAt, createdAt.plusSeconds(3600));
        when(incidents.findById("incident-1")).thenReturn(Optional.of(incident));
    }

    @Test
    void matchesFunctionSpecificProposalAndExecutorActorsAndReportsLocalIntegritySeparately() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "INCIDENT_CREATED", "Created", Instant.now().minusSeconds(50)),
            new AuditEventEntity("local-2", "incident-1", "POLICY_DECISION", "Allowed", Instant.now().minusSeconds(40), 42L, "hash-42", "evaluate-action"),
            new AuditEventEntity("local-3", "incident-1", "REMEDIATION_ACCEPTED", "Accepted", Instant.now().minusSeconds(30), 43L, "hash-43", "execute-remediation"),
            new AuditEventEntity("local-4", "incident-1", "REMEDIATION_VERIFIED", "Verified", Instant.now().minusSeconds(20), 44L, "hash-44", "verify-remediation")
        );
        local(local, AuditIntegrityState.VERIFIED);
        availableIdentity();
        whenActivity(100, new ActivityPage(List.of(
            activity(45, "ignored", "evaluate-action", "did:t3n:agent", "did:t3n:tenant", "z:other:contract"),
            activity(44, "hash-44", "verify-remediation", "did:t3n:executor", "did:t3n:tenant", "z:tenant:privacy-guard"),
            activity(43, "hash-43", "execute-remediation", "did:t3n:executor", "did:t3n:tenant", "z:tenant:privacy-guard"),
            activity(42, "hash-42", "evaluate-action", "did:t3n:agent", "did:t3n:tenant", "z:tenant:privacy-guard")
        ), null, true));

        var result = service.read("incident-1", 100);

        assertThat(result.integrity().state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(result.localEvents()).extracting(event -> event.status()).containsExactly(
            AuditReconciliationStatus.LOCAL_ONLY,
            AuditReconciliationStatus.MATCHED,
            AuditReconciliationStatus.MATCHED,
            AuditReconciliationStatus.MATCHED
        );
        assertThat(result.t3nEvents()).extracting(event -> event.sequence()).containsExactly(44L, 43L, 42L);
        assertThat(result.t3nEvents()).extracting(event -> event.status()).containsOnly(AuditReconciliationStatus.MATCHED);
        assertThat(result.provenance().matched()).isEqualTo(3);
        assertThat(result.provenance().unmatched()).isZero();
        assertThat(result.provenance().t3nOnly()).isZero();
    }

    @Test
    void brokenLocalIntegrityIsReportedWithoutFabricatingOrSuppressingNetworkProvenance() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), 42L, "hash-42", "evaluate-action")
        );
        local(local, AuditIntegrityState.BROKEN);
        availableIdentity();
        whenActivity(100, new ActivityPage(List.of(
            activity(42, "hash-42", "evaluate-action", "did:t3n:agent", "did:t3n:tenant", "z:tenant:privacy-guard")
        ), null, true));

        var result = service.read("incident-1", 100);

        assertThat(result.integrity().state()).isEqualTo(AuditIntegrityState.BROKEN);
        assertThat(result.localEvents().getFirst().status()).isEqualTo(AuditReconciliationStatus.MATCHED);
        assertThat(result.provenance().matched()).isEqualTo(1);
    }

    @Test
    void swappedActorsNeverMatchAndRemainVisibleAsT3nOnly() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), 52L, "hash-52", "evaluate-action"),
            new AuditEventEntity("local-2", "incident-1", "REMEDIATION_ACCEPTED", "Accepted", Instant.now(), 53L, "hash-53", "execute-remediation"),
            new AuditEventEntity("local-3", "incident-1", "REMEDIATION_VERIFIED", "Verified", Instant.now(), 54L, "hash-54", "verify-remediation")
        );
        local(local, AuditIntegrityState.VERIFIED);
        availableIdentity();
        whenActivity(100, new ActivityPage(List.of(
            activity(54, "hash-54", "verify-remediation", "did:t3n:agent", "did:t3n:tenant", "z:tenant:privacy-guard"),
            activity(53, "hash-53", "execute-remediation", "did:t3n:agent", "did:t3n:tenant", "z:tenant:privacy-guard"),
            activity(52, "hash-52", "evaluate-action", "did:t3n:executor", "did:t3n:tenant", "z:tenant:privacy-guard")
        ), null, true));

        var result = service.read("incident-1", 100);

        assertThat(result.localEvents()).extracting(event -> event.status()).containsOnly(AuditReconciliationStatus.UNMATCHED);
        assertThat(result.t3nEvents()).extracting(event -> event.status()).containsOnly(AuditReconciliationStatus.T3N_ONLY);
        assertThat(result.provenance().matched()).isZero();
        assertThat(result.provenance().unmatched()).isEqualTo(3);
        assertThat(result.provenance().t3nOnly()).isEqualTo(3);
    }

    @Test
    void executorUnavailableDoesNotBlockProposalReconciliationOrFabricateProtectedMatch() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), 62L, "hash-62", "evaluate-action"),
            new AuditEventEntity("local-2", "incident-1", "REMEDIATION_ACCEPTED", "Accepted", Instant.now(), 63L, "hash-63", "execute-remediation")
        );
        local(local, AuditIntegrityState.VERIFIED);
        availableTenantAndContract();
        when(gateway.agentStatus()).thenReturn(Optional.of(new GatewaySystemClient.AgentStatus(true, true, true, "did:t3n:agent", "testnet")));
        when(gateway.executorStatus()).thenReturn(Optional.empty());
        whenActivity(100, new ActivityPage(List.of(
            activity(63, "hash-63", "execute-remediation", "did:t3n:executor", "did:t3n:tenant", "z:tenant:privacy-guard"),
            activity(62, "hash-62", "evaluate-action", "did:t3n:agent", "did:t3n:tenant", "z:tenant:privacy-guard")
        ), null, true));

        var result = service.read("incident-1", 100);

        assertThat(result.localEvents()).extracting(event -> event.status()).containsExactly(
            AuditReconciliationStatus.MATCHED,
            AuditReconciliationStatus.UNMATCHED
        );
        assertThat(result.t3nEvents()).extracting(event -> event.status()).containsExactly(
            AuditReconciliationStatus.T3N_ONLY,
            AuditReconciliationStatus.MATCHED
        );
        assertThat(result.provenance().t3nAvailable()).isTrue();
        assertThat(result.provenance().message()).contains("canonical principal identities are unavailable");
    }

    @Test
    void proposalUnavailableDoesNotBlockExecutorReconciliationOrFabricateEvaluationMatch() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), 72L, "hash-72", "evaluate-action"),
            new AuditEventEntity("local-2", "incident-1", "REMEDIATION_VERIFIED", "Verified", Instant.now(), 73L, "hash-73", "verify-remediation")
        );
        local(local, AuditIntegrityState.VERIFIED);
        availableTenantAndContract();
        when(gateway.agentStatus()).thenReturn(Optional.empty());
        when(gateway.executorStatus()).thenReturn(Optional.of(new GatewaySystemClient.ExecutorStatus(true, true, true, "did:t3n:executor", "testnet")));
        whenActivity(100, new ActivityPage(List.of(
            activity(73, "hash-73", "verify-remediation", "did:t3n:executor", "did:t3n:tenant", "z:tenant:privacy-guard"),
            activity(72, "hash-72", "evaluate-action", "did:t3n:agent", "did:t3n:tenant", "z:tenant:privacy-guard")
        ), null, true));

        var result = service.read("incident-1", 100);

        assertThat(result.localEvents()).extracting(event -> event.status()).containsExactly(
            AuditReconciliationStatus.UNMATCHED,
            AuditReconciliationStatus.MATCHED
        );
        assertThat(result.provenance().t3nAvailable()).isTrue();
        assertThat(result.provenance().matched()).isEqualTo(1);
        assertThat(result.provenance().unmatched()).isEqualTo(1);
    }

    @Test
    void hashMismatchIsUnmatchedAndNeverFallsBackToApproximation() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), 82L, "different-hash", "evaluate-action")
        );
        local(local, AuditIntegrityState.VERIFIED);
        availableIdentity();
        whenActivity(100, new ActivityPage(List.of(
            activity(82, "hash-82", "evaluate-action", "did:t3n:agent", "did:t3n:tenant", "z:tenant:privacy-guard")
        ), null, true));

        var result = service.read("incident-1", 100);

        assertThat(result.localEvents().getFirst().status()).isEqualTo(AuditReconciliationStatus.UNMATCHED);
        assertThat(result.t3nEvents().getFirst().status()).isEqualTo(AuditReconciliationStatus.T3N_ONLY);
        assertThat(result.provenance().matched()).isZero();
    }

    @Test
    void tenantAndContractMustMatchExactly() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), 92L, "hash-92", "evaluate-action")
        );
        local(local, AuditIntegrityState.VERIFIED);
        availableIdentity();
        whenActivity(100, new ActivityPage(List.of(
            activity(93, "hash-93", "evaluate-action", "did:t3n:agent", "did:t3n:tenant", "z:other:contract"),
            activity(92, "hash-92", "evaluate-action", "did:t3n:agent", "did:t3n:other-tenant", "z:tenant:privacy-guard")
        ), null, true));

        var result = service.read("incident-1", 100);

        assertThat(result.localEvents().getFirst().status()).isEqualTo(AuditReconciliationStatus.UNMATCHED);
        assertThat(result.t3nEvents()).isEmpty();
        assertThat(result.provenance().matched()).isZero();
    }

    @Test
    void truncatedActivityWindowKeepsExistingIncompletenessSemantics() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), 102L, "hash-102", "evaluate-action")
        );
        local(local, AuditIntegrityState.VERIFIED);
        availableIdentity();
        whenActivity(100, new ActivityPage(List.of(
            activity(102, "hash-102", "evaluate-action", "did:t3n:agent", "did:t3n:tenant", "z:tenant:privacy-guard")
        ), 101L, false));

        var result = service.read("incident-1", 100);

        assertThat(result.localEvents().getFirst().status()).isEqualTo(AuditReconciliationStatus.MATCHED);
        assertThat(result.provenance().t3nComplete()).isFalse();
        assertThat(result.provenance().message()).contains("bounded activity window was truncated");
        assertThat(result.nextSequence()).isEqualTo(101L);
    }

    @Test
    void preservesVerifiedLocalIntegrityWhenT3nActivityIsUnavailable() {
        List<AuditEventEntity> local = List.of(
            new AuditEventEntity("local-1", "incident-1", "INCIDENT_CREATED", "Created", Instant.now()),
            new AuditEventEntity("local-2", "incident-1", "POLICY_DECISION", "Allowed", Instant.now(), null, null, "evaluate-action")
        );
        local(local, AuditIntegrityState.VERIFIED);
        when(gateway.tenantStatus()).thenReturn(Optional.empty());

        var result = service.read("incident-1", 100);

        assertThat(result.integrity().state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(result.localEvents()).hasSize(2);
        assertThat(result.t3nEvents()).isEmpty();
        assertThat(result.provenance().t3nAvailable()).isFalse();
        assertThat(result.provenance().message()).isEqualTo("T3N activity temporarily unavailable. Local business audit remains available; network provenance was not verified.");
    }

    private void local(List<AuditEventEntity> events, AuditIntegrityState state) {
        int checked = state == AuditIntegrityState.VERIFIED ? events.size() : 0;
        when(auditIntegrity.verify("incident-1")).thenReturn(new AuditIntegrityService.Verification(
            state,
            checked,
            state == AuditIntegrityState.VERIFIED ? "a".repeat(64) : null,
            "v1",
            state == AuditIntegrityState.VERIFIED ? "verified" : "integrity failure",
            events
        ));
    }

    private void availableIdentity() {
        availableTenantAndContract();
        when(gateway.agentStatus()).thenReturn(Optional.of(new GatewaySystemClient.AgentStatus(true, true, true, "did:t3n:agent", "testnet")));
        when(gateway.executorStatus()).thenReturn(Optional.of(new GatewaySystemClient.ExecutorStatus(true, true, true, "did:t3n:executor", "testnet")));
    }

    private void availableTenantAndContract() {
        when(gateway.tenantStatus()).thenReturn(Optional.of(new GatewaySystemClient.TenantStatus(true, true, "did:t3n:tenant", "testnet")));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new GatewaySystemClient.ContractIdentity("z:tenant:privacy-guard", "1")));
    }

    private void whenActivity(int limit, ActivityPage page) {
        when(gateway.activity(org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.anyLong(), org.mockito.ArgumentMatchers.eq(limit)))
            .thenReturn(Optional.of(page));
    }

    private static ActivityEvent activity(
        long sequence,
        String hash,
        String function,
        String actorDid,
        String onBehalfOfDid,
        String contractId
    ) {
        return new ActivityEvent(
            sequence,
            hash,
            Instant.now().toEpochMilli(),
            "agent",
            actorDid,
            onBehalfOfDid,
            contractId,
            function,
            "success",
            List.of("incident-agent")
        );
    }
}
