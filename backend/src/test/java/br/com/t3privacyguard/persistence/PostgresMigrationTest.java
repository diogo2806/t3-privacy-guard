package br.com.t3privacyguard.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.t3privacyguard.api.ApiModels.CreateActionRequest;
import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.audit.AuditIntegrityService;
import br.com.t3privacyguard.audit.AuditIntegrityState;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.privacy.IncidentRetentionService;
import br.com.t3privacyguard.service.IncidentService;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * The production profile against a real PostgreSQL: Flyway builds the schema from the versioned migrations and
 * Hibernate validates it against the entities (the context does not start if they drift apart). Then the paths that
 * depend on database behaviour run for real: row locks for the audit chain, the HMAC chain itself, retention purge.
 */
@SpringBootTest
@ActiveProfiles("postgres")
class PostgresMigrationTest {
    private static EmbeddedPostgres postgres;

    @Autowired IncidentService incidents;
    @Autowired AuditIntegrityService auditIntegrity;
    @Autowired IncidentRetentionService retention;
    @Autowired JdbcTemplate jdbc;

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) throws IOException {
        postgres = EmbeddedPostgres.start();
        registry.add("spring.datasource.url", () -> postgres.getJdbcUrl("postgres", "postgres"));
        registry.add("spring.datasource.username", () -> "postgres");
        registry.add("spring.datasource.password", () -> "");
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
    }

    @AfterAll
    static void stop() throws IOException {
        postgres.close();
    }

    @Test
    void migrationsMatchTheEntitiesAndTheMainFlowsPersist() {
        assertThat(jdbc.queryForObject("select max(version) from flyway_schema_history", String.class)).isEqualTo("1");

        var incident = incidents.createIncident(new CreateIncidentRequest("Leaked credential", Severity.HIGH, "Credential found in a paste", "postgres-test"));
        var action = incidents.addAction(incident.id(), new CreateActionRequest(
            "pg-req-1", "revoke-credential", "credential:cred-42", "incident-remediation", "security.example",
            List.of("incident_id", "credential_id", "reason"), List.of()));

        assertThat(incidents.listActions(incident.id())).extracting(saved -> saved.id()).containsExactly(action.id());
        assertThat(incidents.history(incident.id())).extracting(event -> event.type()).contains("INCIDENT_CREATED");
        assertThat(auditIntegrity.verify(incident.id()).state()).isEqualTo(AuditIntegrityState.VERIFIED);

        jdbc.update("update incidents set expires_at = ? where id = ?", java.sql.Timestamp.from(Instant.now().minusSeconds(60)), incident.id());
        assertThat(retention.purgeExpired()).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from audit_events where incident_id = ?", Integer.class, incident.id())).isZero();
    }
}
