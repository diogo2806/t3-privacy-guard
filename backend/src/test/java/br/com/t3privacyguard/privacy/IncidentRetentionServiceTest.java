package br.com.t3privacyguard.privacy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.ExecutionTraceEventEntity;
import br.com.t3privacyguard.persistence.ExecutionTraceEventRepository;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionEntity;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import br.com.t3privacyguard.service.IncidentNotFoundException;
import br.com.t3privacyguard.service.IncidentService;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

@SpringBootTest
class IncidentRetentionServiceTest {
    @Autowired IncidentRetentionService retention;
    @Autowired IncidentRetentionProperties properties;
    @Autowired IncidentService incidentService;
    @Autowired IncidentRepository incidents;
    @Autowired ActionProposalRepository actions;
    @Autowired PolicyDecisionRepository decisions;
    @Autowired RemediationExecutionRepository remediations;
    @Autowired ExecutionTraceEventRepository traces;
    @Autowired AuditEventRepository audits;
    @Autowired JdbcTemplate jdbc;

    @BeforeEach
    void clear() {
        remediations.deleteAll();
        decisions.deleteAll();
        traces.deleteAll();
        actions.deleteAll();
        audits.deleteAll();
        incidents.deleteAll();
    }

    @Test
    void expiredIncidentIsHiddenBeforePurgeAndHardDeletedWithDependents() {
        Instant now = Instant.now();
        String incidentId = "incident-expired";
        String actionId = "action-expired";
        incidents.save(new IncidentEntity(
            incidentId, "Expired incident", Severity.HIGH, "Synthetic summary", "test", now.minus(Duration.ofDays(8)), now.minusSeconds(1)
        ));
        actions.save(new ActionProposalEntity(
            actionId, incidentId, "request-expired", "revoke-credential", "credential:test", "incident-remediation",
            "postman-echo.com", "[\"incident_id\"]", "[]", now.minus(Duration.ofDays(8))
        ));
        decisions.save(new PolicyDecisionEntity(
            "decision-expired", actionId, DecisionType.ALLOW, "POLICY_ALLOW", "Allowed",
            "[\"incident_id\"]", "[]", "[]", "[]", now.minus(Duration.ofDays(8))
        ));
        remediations.save(new RemediationExecutionEntity("remediation-expired", actionId, "request-expired", now.minus(Duration.ofDays(8))));
        traces.save(new ExecutionTraceEventEntity(
            "trace-expired", incidentId, actionId, "request-expired", "trace-id-expired",
            "EXTERNAL_VERIFICATION", "VERIFIED", null, 12L, now.minus(Duration.ofDays(8))
        ));
        audits.save(new AuditEventEntity("audit-expired", incidentId, "INCIDENT_CREATED", "Synthetic audit", now.minus(Duration.ofDays(8))));

        assertThat(incidentService.listIncidents()).isEmpty();
        assertThatThrownBy(() -> incidentService.getIncident(incidentId)).isInstanceOf(IncidentNotFoundException.class);
        assertThat(incidents.count()).isEqualTo(1);

        assertThat(retention.purgeExpired()).isEqualTo(1);
        assertThat(remediations.count()).isZero();
        assertThat(decisions.count()).isZero();
        assertThat(traces.count()).isZero();
        assertThat(actions.count()).isZero();
        assertThat(audits.count()).isZero();
        assertThat(incidents.count()).isZero();
        assertThat(retention.purgeExpired()).isZero();
    }

    @Test
    void activeIncidentIsNotPurged() {
        Instant now = Instant.now();
        incidents.save(new IncidentEntity(
            "incident-active", "Active incident", Severity.LOW, "Synthetic summary", "test", now, now.plus(properties.retention())
        ));

        assertThat(retention.purgeExpired()).isZero();
        assertThat(incidents.count()).isEqualTo(1);
        assertThat(incidentService.listIncidents()).extracting(item -> item.id()).containsExactly("incident-active");
    }

    @Test
    void startupBackfillsLegacyExpiryUsingServerRetentionFormula() {
        Instant createdAt = Instant.now().minus(Duration.ofDays(1));
        jdbc.update(
            "insert into incidents (id, title, severity, summary, source, status, created_at, expires_at) values (?, ?, ?, ?, ?, ?, ?, null)",
            "incident-legacy", "Legacy incident", "MEDIUM", "Synthetic summary", "legacy-test", "OPEN", createdAt
        );

        retention.initializeRetention();

        IncidentEntity stored = incidents.findById("incident-legacy").orElseThrow();
        assertThat(stored.getExpiresAt()).isEqualTo(stored.getCreatedAt().plus(properties.retention()));
    }
}
