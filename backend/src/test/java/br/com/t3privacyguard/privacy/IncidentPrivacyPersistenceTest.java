package br.com.t3privacyguard.privacy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.service.IncidentService;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class IncidentPrivacyPersistenceTest {
    @Autowired IncidentService service;
    @Autowired IncidentRepository incidents;
    @Autowired AuditEventRepository audits;
    @Autowired IncidentRetentionProperties retentionProperties;

    @BeforeEach
    void clear() {
        audits.deleteAll();
        incidents.deleteAll();
    }

    @Test
    void createdIncidentHasServerControlledExpiryAndMinimizedSummary() {
        var response = service.createIncident(new CreateIncidentRequest(
            "  Retention   test  ",
            Severity.HIGH,
            "A".repeat(1500),
            "  synthetic   test  "
        ));

        assertThat(response.title()).isEqualTo("Retention test");
        assertThat(response.summary()).hasSize(IncidentDataMinimizer.MAX_SUMMARY_LENGTH);
        assertThat(response.source()).isEqualTo("synthetic test");
        assertThat(response.retentionState()).isEqualTo("ACTIVE");
        assertThat(Duration.between(response.createdAt(), response.expiresAt()))
            .isEqualTo(retentionProperties.retention());
        assertThat(incidents.findById(response.id()).orElseThrow().getExpiresAt()).isEqualTo(response.expiresAt());
    }

    @Test
    void sensitiveSentinelNeverReachesIncidentOrAuditPersistence() {
        String sentinel = "api_key=sk-1234567890abcdefghijklmnop";

        assertThatThrownBy(() -> service.createIncident(new CreateIncidentRequest(
            "Unsafe incident",
            Severity.CRITICAL,
            "Detected " + sentinel,
            "test-source"
        ))).isInstanceOf(UnsafeIncidentContentException.class);

        assertThat(incidents.count()).isZero();
        assertThat(audits.count()).isZero();
    }
}
