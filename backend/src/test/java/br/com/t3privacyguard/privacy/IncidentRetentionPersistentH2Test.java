package br.com.t3privacyguard.privacy;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.service.IncidentService;
import java.sql.Timestamp;
import java.time.Duration;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;

@SpringBootTest(properties = {
    "spring.datasource.url=jdbc:h2:file:./target/incident-retention-persistent-it;AUTO_SERVER=TRUE;DB_CLOSE_ON_EXIT=FALSE",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "privacy-guard.incident-retention.days=7",
    "privacy-guard.incident-retention.purge-initial-delay-ms=86400000",
    "privacy-guard.incident-retention.purge-interval-ms=86400000"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class IncidentRetentionPersistentH2Test {
    @Autowired IncidentService service;
    @Autowired IncidentRepository incidents;
    @Autowired JdbcTemplate jdbc;
    @Autowired DataSource dataSource;

    @Test
    void persistsExpirationMetadataInFileBackedH2() throws Exception {
        incidents.deleteAll();
        var created = service.createIncident(new CreateIncidentRequest(
            "Persistent H2 retention",
            Severity.MEDIUM,
            "Synthetic operational summary",
            "persistent-h2-test"
        ));

        try (var connection = dataSource.getConnection()) {
            assertThat(connection.getMetaData().getURL()).startsWith("jdbc:h2:file:");
        }

        Timestamp storedExpiry = jdbc.queryForObject(
            "select expires_at from incidents where id = ?",
            Timestamp.class,
            created.id()
        );

        assertThat(storedExpiry).isNotNull();
        assertThat(storedExpiry.toInstant()).isEqualTo(created.expiresAt());
        assertThat(Duration.between(created.createdAt(), created.expiresAt())).isEqualTo(Duration.ofDays(7));
    }
}
