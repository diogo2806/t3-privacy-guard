package br.com.t3privacyguard.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@AutoConfigureMockMvc
class AuditEvidenceExpiryIntegrationTest {
    @Autowired
    MockMvc mvc;

    @Autowired
    IncidentRepository incidents;

    @Test
    @Transactional
    void expiredIncidentRemainsPersistedButAuditEvidenceIsAlreadyHidden() throws Exception {
        Instant now = Instant.now();
        String incidentId = "expired-audit-evidence-integration";
        incidents.saveAndFlush(new IncidentEntity(
            incidentId,
            "Expired incident",
            Severity.HIGH,
            "Expired but still physically persisted",
            "integration-test",
            now.minusSeconds(3600),
            now.minusSeconds(1)
        ));

        assertThat(incidents.findById(incidentId)).isPresent();

        mvc.perform(get("/api/incidents/{incidentId}/audit-evidence", incidentId)
                .with(user("test-operator").roles("OPERATOR")))
            .andExpect(status().isNotFound())
            .andExpect(jsonPath("$.detail").value("Incident not found"));

        assertThat(incidents.findById(incidentId)).isPresent();
    }
}
