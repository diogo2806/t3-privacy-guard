package br.com.t3privacyguard.audit;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.t3privacyguard.domain.AuditIntegrityState;
import br.com.t3privacyguard.persistence.AuditChainHeadRepository;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuditIntegrityTamperingTest {
    @Autowired AuditIntegrityService service;
    @Autowired AuditEventRepository audits;
    @Autowired AuditChainHeadRepository heads;

    @AfterEach
    void clean() {
        audits.deleteAll();
        heads.deleteAll();
    }

    @Test
    void changedTypeTimestampPreviousMacOrEventMacIsBroken() {
        AuditEventEntity original = service.append("incident-fields", "INCIDENT_CREATED", "Created", null, null, null);

        assertBroken(copy(original, "CHANGED_TYPE", original.getCreatedAt(), original.getIntegritySequence(), original.getPreviousMac(), original.getEventMac()));
        assertBroken(copy(original, original.getType(), original.getCreatedAt().plusSeconds(1), original.getIntegritySequence(), original.getPreviousMac(), original.getEventMac()));
        assertBroken(copy(original, original.getType(), original.getCreatedAt(), original.getIntegritySequence(), "0".repeat(64), original.getEventMac()));
        assertBroken(copy(original, original.getType(), original.getCreatedAt(), original.getIntegritySequence(), original.getPreviousMac(), "1".repeat(64)));
    }

    @Test
    void duplicateSequenceIsBrokenEvenIfRowsAreSuppliedOutOfBand() {
        AuditEventEntity first = service.append("incident-duplicate", "INCIDENT_CREATED", "Created", null, null, null);
        AuditEventEntity second = service.append("incident-duplicate", "ACTION_PROPOSED", "Proposed", null, null, null);
        AuditEventEntity duplicate = copy(
            second,
            second.getType(),
            second.getCreatedAt(),
            first.getIntegritySequence(),
            second.getPreviousMac(),
            second.getEventMac()
        );

        var result = service.verify("incident-duplicate", List.of(first, duplicate));
        assertThat(result.state()).isEqualTo(AuditIntegrityState.BROKEN);
        assertThat(result.message()).contains("sequence");
    }

    @Test
    void deletedMiddleRowProducesGapAndIsBroken() {
        AuditEventEntity first = service.append("incident-middle-delete", "INCIDENT_CREATED", "Created", null, null, null);
        service.append("incident-middle-delete", "ACTION_PROPOSED", "Proposed", null, null, null);
        AuditEventEntity third = service.append("incident-middle-delete", "POLICY_DECISION", "Denied", null, null, null);

        var result = service.verify("incident-middle-delete", List.of(first, third));
        assertThat(result.state()).isEqualTo(AuditIntegrityState.BROKEN);
        assertThat(result.message()).contains("sequence");
    }

    private void assertBroken(AuditEventEntity tampered) {
        var result = service.verify(tampered.getIncidentId(), List.of(tampered));
        assertThat(result.state()).isEqualTo(AuditIntegrityState.BROKEN);
    }

    private static AuditEventEntity copy(
        AuditEventEntity source,
        String type,
        Instant createdAt,
        Long sequence,
        String previousMac,
        String eventMac
    ) {
        return new AuditEventEntity(
            source.getId(),
            source.getIncidentId(),
            type,
            source.getMessage(),
            createdAt,
            source.getT3nSequence(),
            source.getT3nHash(),
            source.getT3nFunction(),
            sequence,
            previousMac,
            eventMac,
            source.getIntegrityVersion()
        );
    }
}
