package br.com.t3privacyguard.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.persistence.AuditChainHeadRepository;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuditIntegrityServiceTest {
    @Autowired AuditIntegrityService integrity;
    @Autowired AuditEventRepository audits;
    @Autowired AuditChainHeadRepository heads;
    @Autowired IncidentRepository incidents;

    @BeforeEach
    void clear() {
        heads.deleteAll();
        audits.deleteAll();
        incidents.deleteAll();
    }

    @Test
    void canonicalPayloadAndKnownHmacAreStable() {
        String payload = AuditMac.canonicalEvent(
            "k1",
            "incident-1",
            "event-1",
            1,
            "INCIDENT_CREATED",
            Instant.parse("2026-09-12T20:00:00Z"),
            "Incident created",
            AuditMac.GENESIS
        );

        assertThat(payload).isEqualTo(
            "v1\n" +
            "k1\n" +
            "aW5jaWRlbnQtMQ\n" +
            "ZXZlbnQtMQ\n" +
            "1\n" +
            "SU5DSURFTlRfQ1JFQVRFRA\n" +
            "2026-09-12T20:00:00Z\n" +
            "SW5jaWRlbnQgY3JlYXRlZA\n" +
            AuditMac.GENESIS
        );
        assertThat(AuditMac.hmacHex(
            "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8),
            payload
        )).isEqualTo("4f9916324a4e1fe0a7092c92afaa6f081e68e6376e42e6f3a56c0ffbdc18eb9e");
    }

    @Test
    void oneAndMultipleEventsVerifyAsLinearChain() {
        String incidentId = incident();
        integrity.append(incidentId, "INCIDENT_CREATED", "Created");
        integrity.append(incidentId, "ACTION_PROPOSED", "Action proposed");
        integrity.append(incidentId, "POLICY_DECISION", "Policy denied");

        var verification = integrity.verify(incidentId);

        assertThat(verification.state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(verification.eventsChecked()).isEqualTo(3);
        assertThat(verification.events()).extracting(AuditEventEntity::getSequence).containsExactly(1L, 2L, 3L);
        assertThat(verification.head()).hasSize(64);
    }

    @Test
    void changedMessageIsDetected() {
        String incidentId = incidentWithTwoEvents();
        AuditEventEntity event = events(incidentId).get(0);
        audits.saveAndFlush(copy(event, event.getSequence(), event.getPreviousMac(), event.getEventMac(), event.getIntegrityKeyId(), "tampered"));

        assertThat(integrity.verify(incidentId).state()).isEqualTo(AuditIntegrityState.BROKEN);
    }

    @Test
    void changedEventIdIsDetected() {
        String incidentId = incidentWithTwoEvents();
        AuditEventEntity event = events(incidentId).get(0);
        audits.deleteById(event.getId());
        audits.flush();
        audits.saveAndFlush(new AuditEventEntity(
            "replacement-event-id",
            event.getIncidentId(),
            event.getType(),
            event.getMessage(),
            event.getCreatedAt(),
            event.getSequence(),
            event.getPreviousMac(),
            event.getEventMac(),
            event.getIntegrityVersion(),
            event.getIntegrityKeyId()
        ));

        assertThat(integrity.verify(incidentId).state()).isEqualTo(AuditIntegrityState.BROKEN);
    }

    @Test
    void deletedTailIsDetectedByAuthenticatedHead() {
        String incidentId = incidentWithTwoEvents();
        List<AuditEventEntity> stored = events(incidentId);
        audits.deleteById(stored.get(stored.size() - 1).getId());
        audits.flush();

        assertThat(integrity.verify(incidentId).state()).isEqualTo(AuditIntegrityState.BROKEN);
    }

    @Test
    void insertedLegacyLikeRowAfterProtectedEventsIsDetected() {
        String incidentId = incidentWithTwoEvents();
        Instant afterTail = events(incidentId).get(1).getCreatedAt().plusMillis(1);
        audits.saveAndFlush(new AuditEventEntity(UUID.randomUUID().toString(), incidentId, "MANUAL_INSERT", "manual", afterTail));

        assertThat(integrity.verify(incidentId).state()).isEqualTo(AuditIntegrityState.BROKEN);
    }

    @Test
    void sequenceOrLinkTamperIsDetected() {
        String incidentId = incidentWithTwoEvents();
        AuditEventEntity second = events(incidentId).get(1);
        audits.saveAndFlush(copy(second, 1L, "f".repeat(64), second.getEventMac(), second.getIntegrityKeyId(), second.getMessage()));

        assertThat(integrity.verify(incidentId).state()).isEqualTo(AuditIntegrityState.BROKEN);
    }

    @Test
    void missingConfiguredHistoricalKeyIsExplicit() {
        String incidentId = incidentWithTwoEvents();
        AuditEventEntity first = events(incidentId).get(0);
        audits.saveAndFlush(copy(first, first.getSequence(), first.getPreviousMac(), first.getEventMac(), "retired-key-not-configured", first.getMessage()));

        assertThat(integrity.verify(incidentId).state()).isEqualTo(AuditIntegrityState.KEY_MISMATCH);
    }

    @Test
    void legacyRowsRemainExplicitlyUnverified() {
        String incidentId = incident();
        audits.saveAndFlush(new AuditEventEntity(
            UUID.randomUUID().toString(), incidentId, "LEGACY_EVENT", "legacy", Instant.parse("2026-01-01T00:00:00Z")
        ));

        var verification = integrity.verify(incidentId);

        assertThat(verification.state()).isEqualTo(AuditIntegrityState.LEGACY_UNVERIFIED);
        assertThat(verification.eventsChecked()).isZero();
        assertThat(verification.head()).isNull();
    }

    @Test
    void legacyHistoryCannotSilentlyBecomeANewTrustRoot() {
        String incidentId = incident();
        audits.saveAndFlush(new AuditEventEntity(
            UUID.randomUUID().toString(), incidentId, "LEGACY_EVENT", "legacy", Instant.parse("2026-01-01T00:00:00Z")
        ));

        assertThatThrownBy(() -> integrity.append(incidentId, "ACTION_PROPOSED", "new event"))
            .isInstanceOf(AuditIntegrityException.class)
            .hasMessageContaining("Legacy audit bootstrap is disabled");
        assertThat(heads.findById(incidentId)).isEmpty();
    }

    @Test
    void concurrentAppendsReceiveUniqueLinearSequences() throws Exception {
        String incidentId = incident();
        integrity.append(incidentId, "INCIDENT_CREATED", "Created");
        CountDownLatch start = new CountDownLatch(1);

        CompletableFuture<Void> first = CompletableFuture.runAsync(() -> {
            await(start);
            integrity.append(incidentId, "CONCURRENT_A", "A");
        });
        CompletableFuture<Void> second = CompletableFuture.runAsync(() -> {
            await(start);
            integrity.append(incidentId, "CONCURRENT_B", "B");
        });
        start.countDown();
        CompletableFuture.allOf(first, second).get(10, TimeUnit.SECONDS);

        var verification = integrity.verify(incidentId);
        assertThat(verification.state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(verification.events()).extracting(AuditEventEntity::getSequence).containsExactly(1L, 2L, 3L);
    }

    @Test
    void missingEventsWithoutRetentionMarkerAreBrokenNotVerified() {
        String incidentId = incident();
        assertThat(integrity.verify(incidentId).state()).isEqualTo(AuditIntegrityState.BROKEN);
    }

    private String incidentWithTwoEvents() {
        String incidentId = incident();
        integrity.append(incidentId, "INCIDENT_CREATED", "Created");
        integrity.append(incidentId, "ACTION_PROPOSED", "Action proposed");
        return incidentId;
    }

    private String incident() {
        String id = UUID.randomUUID().toString();
        incidents.saveAndFlush(new IncidentEntity(id, "Synthetic", Severity.CRITICAL, "Synthetic incident", "test", Instant.now()));
        return id;
    }

    private List<AuditEventEntity> events(String incidentId) {
        return audits.findByIncidentIdOrderByCreatedAtAscIdAsc(incidentId);
    }

    private AuditEventEntity copy(
        AuditEventEntity source,
        Long sequence,
        String previousMac,
        String eventMac,
        String keyId,
        String message
    ) {
        return new AuditEventEntity(
            source.getId(),
            source.getIncidentId(),
            source.getType(),
            message,
            source.getCreatedAt(),
            sequence,
            previousMac,
            eventMac,
            source.getIntegrityVersion(),
            keyId
        );
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Concurrent audit test did not start in time");
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(ex);
        }
    }
}
