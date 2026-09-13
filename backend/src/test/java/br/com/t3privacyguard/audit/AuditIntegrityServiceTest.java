package br.com.t3privacyguard.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.domain.AuditIntegrityState;
import br.com.t3privacyguard.persistence.AuditChainHeadRepository;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.privacy.IncidentDataMinimizer;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuditIntegrityServiceTest {
    private static final String KEY = "test-audit-integrity-key-12345678901234567890";

    @Autowired AuditIntegrityService service;
    @Autowired AuditEventRepository audits;
    @Autowired AuditChainHeadRepository heads;
    @Autowired IncidentDataMinimizer minimizer;

    @AfterEach
    void clean() {
        audits.deleteAll();
        heads.deleteAll();
    }

    @Test
    void canonicalPayloadHasStableKnownHmac() {
        String mac = AuditIntegrityService.calculateMac(
            "audit-integrity-test-key-12345678901234567890".getBytes(StandardCharsets.UTF_8),
            "incident-1",
            1,
            "INCIDENT_CREATED",
            Instant.parse("2026-09-12T22:00:00Z"),
            "Incident created",
            AuditIntegrityService.GENESIS_MAC
        );

        assertThat(mac).isEqualTo("7d090ba8f4f88d170f576e59c468deb9e2f173dd1cf180c16f1cf4f8651d7152");
    }

    @Test
    void oneAndManyEventsVerifyAsLinearChain() {
        service.append("incident-chain", "INCIDENT_CREATED", "Created", null, null, null);
        service.append("incident-chain", "ACTION_PROPOSED", "Action proposed", null, null, null);
        service.append("incident-chain", "POLICY_DECISION", "Policy decision DENY", 42L, "hash-42", "evaluate-action");

        List<AuditEventEntity> events = audits.findByIncidentIdOrderByCreatedAtAsc("incident-chain");
        var result = service.verify("incident-chain", events);

        assertThat(result.state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(result.eventsChecked()).isEqualTo(3);
        assertThat(result.head()).matches("[a-f0-9]{64}");
        assertThat(events).extracting(AuditEventEntity::getIntegritySequence).containsExactly(1L, 2L, 3L);
        assertThat(events.getFirst().getPreviousMac()).isEqualTo(AuditIntegrityService.GENESIS_MAC);
    }

    @Test
    void changedMessageIsDetectedAsBroken() {
        AuditEventEntity event = service.append("incident-message", "INCIDENT_CREATED", "Original", null, null, null);
        AuditEventEntity tampered = new AuditEventEntity(
            event.getId(), event.getIncidentId(), event.getType(), "Modified directly in storage", event.getCreatedAt(),
            event.getT3nSequence(), event.getT3nHash(), event.getT3nFunction(), event.getIntegritySequence(),
            event.getPreviousMac(), event.getEventMac(), event.getIntegrityVersion()
        );
        audits.saveAndFlush(tampered);

        var result = service.verify("incident-message", audits.findByIncidentIdOrderByCreatedAtAsc("incident-message"));
        assertThat(result.state()).isEqualTo(AuditIntegrityState.BROKEN);
        assertThat(result.message()).contains("MAC");
    }

    @Test
    void deletedTailIsDetectedAgainstPersistedHead() {
        service.append("incident-delete", "INCIDENT_CREATED", "Created", null, null, null);
        AuditEventEntity second = service.append("incident-delete", "ACTION_PROPOSED", "Proposed", null, null, null);
        audits.deleteById(second.getId());
        audits.flush();

        var result = service.verify("incident-delete", audits.findByIncidentIdOrderByCreatedAtAsc("incident-delete"));
        assertThat(result.state()).isEqualTo(AuditIntegrityState.BROKEN);
        assertThat(result.message()).contains("head");
    }

    @Test
    void manuallyInsertedGapOrFakeMacIsDetected() {
        service.append("incident-insert", "INCIDENT_CREATED", "Created", null, null, null);
        audits.saveAndFlush(new AuditEventEntity(
            "manual-row", "incident-insert", "ACTION_PROPOSED", "Inserted", Instant.now(),
            null, null, null, 99L, "0".repeat(64), "1".repeat(64), AuditIntegrityService.INTEGRITY_VERSION
        ));

        var result = service.verify("incident-insert", audits.findByIncidentIdOrderByCreatedAtAsc("incident-insert"));
        assertThat(result.state()).isEqualTo(AuditIntegrityState.BROKEN);
        assertThat(result.message()).contains("sequence");
    }

    @Test
    void concurrentAppendsRemainUniqueAndLinear() throws Exception {
        service.append("incident-concurrent", "INCIDENT_CREATED", "Created", null, null, null);
        var executor = Executors.newFixedThreadPool(6);
        try {
            List<Callable<Void>> tasks = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                int event = i;
                tasks.add(() -> {
                    service.append("incident-concurrent", "ACTION_PROPOSED", "Event " + event, null, null, null);
                    return null;
                });
            }
            List<Future<Void>> futures = executor.invokeAll(tasks);
            for (Future<Void> future : futures) future.get();
        } finally {
            executor.shutdownNow();
        }

        List<AuditEventEntity> events = audits.findByIncidentIdOrderByCreatedAtAsc("incident-concurrent");
        List<Long> sequences = events.stream().map(AuditEventEntity::getIntegritySequence).sorted(Comparator.naturalOrder()).toList();
        assertThat(sequences).containsExactlyElementsOf(java.util.stream.LongStream.rangeClosed(1, 13).boxed().toList());
        assertThat(service.verify("incident-concurrent", events).state()).isEqualTo(AuditIntegrityState.VERIFIED);
    }

    @Test
    void restartWithSameKeyVerifiesAndWrongKeyBreaksWithoutRewritingHistory() {
        service.append("incident-restart", "INCIDENT_CREATED", "Created", null, null, null);
        List<AuditEventEntity> events = audits.findByIncidentIdOrderByCreatedAtAsc("incident-restart");

        AuditIntegrityService sameKey = instance(KEY);
        AuditIntegrityService wrongKey = instance("different-audit-integrity-key-123456789012345");

        assertThat(sameKey.verify("incident-restart", events).state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(wrongKey.verify("incident-restart", events).state()).isEqualTo(AuditIntegrityState.BROKEN);
        assertThat(audits.findByIncidentIdOrderByCreatedAtAsc("incident-restart").getFirst().getEventMac())
            .isEqualTo(events.getFirst().getEventMac());
    }

    @Test
    void legacyRowsRemainExplicitlyUnverified() throws Exception {
        audits.saveAndFlush(new AuditEventEntity(
            "legacy", "incident-legacy", "INCIDENT_CREATED", "Legacy event", Instant.parse("2026-09-01T10:00:00Z")
        ));

        var result = service.verify("incident-legacy", audits.findByIncidentIdOrderByCreatedAtAsc("incident-legacy"));
        assertThat(result.state()).isEqualTo(AuditIntegrityState.LEGACY_UNVERIFIED);
        assertThat(result.eventsChecked()).isZero();
        assertThat(new ObjectMapper().writeValueAsString(result)).doesNotContain(KEY);
    }

    @Test
    void auditKeyMustBeStrongAndDifferentFromOtherCredentials() {
        assertThatThrownBy(() -> new AuditIntegrityService(audits, heads, minimizer, "short", "", "", "", "", "", ""))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("at least 32");
        assertThatThrownBy(() -> new AuditIntegrityService(audits, heads, minimizer, KEY, KEY, "", "", "", "", ""))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("different");
    }

    private AuditIntegrityService instance(String key) {
        return new AuditIntegrityService(audits, heads, minimizer, key, "", "", "", "", "", "");
    }
}
