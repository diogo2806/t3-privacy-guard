package br.com.t3privacyguard.audit;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.persistence.AuditChainHeadRepository;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class AuditIntegrityGuardTest {
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
    void brokenChainBlocksProtectedChangeGate() {
        String incidentId = UUID.randomUUID().toString();
        Instant now = Instant.now();
        incidents.saveAndFlush(new IncidentEntity(
            incidentId,
            "Synthetic",
            Severity.CRITICAL,
            "Synthetic incident",
            "test",
            now,
            now.plusSeconds(3600)
        ));
        AuditEventEntity event = integrity.append(incidentId, "INCIDENT_CREATED", "Created");
        audits.saveAndFlush(new AuditEventEntity(
            event.getId(),
            event.getIncidentId(),
            event.getType(),
            "tampered after persistence",
            event.getCreatedAt(),
            event.getT3nSequence(),
            event.getT3nHash(),
            event.getT3nFunction(),
            event.getSequence(),
            event.getPreviousMac(),
            event.getEventMac(),
            event.getIntegrityVersion(),
            event.getIntegrityKeyId()
        ));

        assertThatThrownBy(() -> integrity.assertAppendable(incidentId))
            .isInstanceOf(AuditIntegrityException.class)
            .hasMessageContaining("protected execution is blocked");
    }
}
