package br.com.t3privacyguard.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import br.com.t3privacyguard.api.ApiModels.IncidentIntakeRequest;
import br.com.t3privacyguard.api.ApiModels.IncidentIntakeResponse;
import br.com.t3privacyguard.domain.IncidentOriginType;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.security.IncidentIntakeCredentialRegistry;
import br.com.t3privacyguard.security.IncidentIntakePrincipal;
import br.com.t3privacyguard.service.IncidentIntakeService;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
    "privacy-guard.incident-intake.enabled=true",
    "privacy-guard.incident-intake.integrations-json=[{\"id\":\"security-automation\",\"name\":\"Security automation\",\"token\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},{\"id\":\"siem-secondary\",\"name\":\"Secondary SIEM\",\"token\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}]"
})
@AutoConfigureMockMvc
class IncidentIntakeIntegrationTest {
    private static final String TOKEN_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private static final String TOKEN_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    @Autowired MockMvc mvc;
    @Autowired IncidentRepository incidents;
    @Autowired AuditEventRepository auditEvents;
    @Autowired ActionProposalRepository actions;
    @Autowired IncidentIntakeService intake;
    @Autowired IncidentIntakeCredentialRegistry credentials;

    @Test
    void validCredentialCreatesMinimizedExternalIncidentWithoutCsrfOrAutomaticAction() throws Exception {
        mvc.perform(post("/api/integrations/incidents")
                .header(HttpHeaders.AUTHORIZATION, bearer(TOKEN_A))
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload("evt-valid-001", "Credential compromise", "Operational security signal without private values.")))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.replayed").value(false))
            .andExpect(jsonPath("$.incident.title").value("Credential compromise"))
            .andExpect(jsonPath("$.incident.source").value("Approved integration: Security automation"))
            .andExpect(jsonPath("$.incident.status").value("OPEN"));

        var stored = incidents.findByIntegrationIdAndExternalEventId("security-automation", "evt-valid-001").orElseThrow();
        assertThat(stored.getOriginType()).isEqualTo(IncidentOriginType.EXTERNAL);
        assertThat(stored.getIntegrationId()).isEqualTo("security-automation");
        assertThat(stored.getExternalEventId()).isEqualTo("evt-valid-001");
        assertThat(Duration.between(stored.getCreatedAt(), stored.getExpiresAt())).isEqualTo(Duration.ofDays(7));
        assertThat(actions.findByIncidentIdOrderByCreatedAtAsc(stored.getId())).isEmpty();

        var audit = auditEvents.findByIncidentIdOrderByCreatedAtAsc(stored.getId());
        assertThat(audit).extracting(event -> event.getType()).contains("INCIDENT_CREATED", "EXTERNAL_INCIDENT_RECEIVED");
        assertThat(audit).extracting(event -> event.getMessage()).allSatisfy(message -> assertThat(message).doesNotContain(TOKEN_A));
    }

    @Test
    void invalidCredentialFailsClosedAndSensitivePayloadIsRejectedBeforePersistence() throws Exception {
        mvc.perform(post("/api/integrations/incidents")
                .header(HttpHeaders.AUTHORIZATION, bearer("cccccccccccccccccccccccccccccccccccccccc"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload("evt-invalid-auth", "Credential compromise", "Operational signal.")))
            .andExpect(status().isUnauthorized());

        mvc.perform(post("/api/integrations/incidents")
                .header(HttpHeaders.AUTHORIZATION, bearer(TOKEN_A))
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload("evt-sensitive-001", "Credential compromise", "Affected account: qa.person@example.com")))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.title").value("Incident content rejected"));

        assertThat(incidents.findByIntegrationIdAndExternalEventId("security-automation", "evt-sensitive-001")).isEmpty();
    }

    @Test
    void sequentialReplayReturnsSameIncidentAndServerIgnoresSpoofedSourceField() throws Exception {
        String body = "{\"externalEventId\":\"evt-replay-001\",\"title\":\"Suspicious credential use\",\"severity\":\"HIGH\",\"summary\":\"Operational signal only.\",\"source\":\"Spoofed source\"}";

        mvc.perform(post("/api/integrations/incidents")
                .header(HttpHeaders.AUTHORIZATION, bearer(TOKEN_A))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.replayed").value(false))
            .andExpect(jsonPath("$.incident.source").value("Approved integration: Security automation"));

        mvc.perform(post("/api/integrations/incidents")
                .header(HttpHeaders.AUTHORIZATION, bearer(TOKEN_A))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.replayed").value(true))
            .andExpect(jsonPath("$.incident.source").value("Approved integration: Security automation"));

        assertThat(incidents.findAll().stream()
            .filter(item -> "security-automation".equals(item.getIntegrationId()) && "evt-replay-001".equals(item.getExternalEventId())))
            .hasSize(1);
    }

    @Test
    void sameExternalEventIdIsIndependentAcrossIntegrations() throws Exception {
        String body = payload("evt-shared-001", "Shared event id", "Operational metadata only.");

        mvc.perform(post("/api/integrations/incidents")
                .header(HttpHeaders.AUTHORIZATION, bearer(TOKEN_A))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.incident.source").value("Approved integration: Security automation"));

        mvc.perform(post("/api/integrations/incidents")
                .header(HttpHeaders.AUTHORIZATION, bearer(TOKEN_B))
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.incident.source").value("Approved integration: Secondary SIEM"));

        var first = incidents.findByIntegrationIdAndExternalEventId("security-automation", "evt-shared-001").orElseThrow();
        var second = incidents.findByIntegrationIdAndExternalEventId("siem-secondary", "evt-shared-001").orElseThrow();
        assertThat(first.getId()).isNotEqualTo(second.getId());
    }

    @Test
    void concurrentReplayConvergesToOnePersistedIncident() throws Exception {
        IncidentIntakePrincipal principal = credentials.authenticate(TOKEN_A).orElseThrow();
        IncidentIntakeRequest request = new IncidentIntakeRequest(
            "evt-concurrent-001",
            "Concurrent signal",
            Severity.CRITICAL,
            "Concurrent operational metadata only."
        );
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Future<IncidentIntakeResponse> first = pool.submit(() -> receiveAfterBarrier(principal, request, ready, start));
            Future<IncidentIntakeResponse> second = pool.submit(() -> receiveAfterBarrier(principal, request, ready, start));
            assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
            start.countDown();

            List<IncidentIntakeResponse> responses = List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
            assertThat(responses).extracting(response -> response.incident().id()).containsOnly(responses.get(0).incident().id());
            assertThat(responses).extracting(IncidentIntakeResponse::replayed).containsExactlyInAnyOrder(false, true);
            assertThat(incidents.findAll().stream()
                .filter(item -> "security-automation".equals(item.getIntegrationId()) && "evt-concurrent-001".equals(item.getExternalEventId())))
                .hasSize(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void intakeCredentialCannotAuthorizeOrExecuteThroughHumanSessionRoutes() throws Exception {
        mvc.perform(post("/api/incidents/missing/actions/missing/authorize-remediation")
                .header(HttpHeaders.AUTHORIZATION, bearer(TOKEN_A)))
            .andExpect(result -> assertThat(result.getResponse().getStatus()).isIn(401, 403));

        mvc.perform(post("/api/incidents/missing/actions/missing/execute-remediation")
                .header(HttpHeaders.AUTHORIZATION, bearer(TOKEN_A)))
            .andExpect(result -> assertThat(result.getResponse().getStatus()).isIn(401, 403));
    }

    private IncidentIntakeResponse receiveAfterBarrier(
        IncidentIntakePrincipal principal,
        IncidentIntakeRequest request,
        CountDownLatch ready,
        CountDownLatch start
    ) throws Exception {
        ready.countDown();
        if (!start.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Concurrent intake barrier timed out");
        return intake.receive(principal, request);
    }

    private static String bearer(String value) {
        return "Bearer " + value;
    }

    private static String payload(String externalEventId, String title, String summary) {
        return "{\"externalEventId\":\"" + externalEventId + "\",\"title\":\"" + title
            + "\",\"severity\":\"CRITICAL\",\"summary\":\"" + summary + "\"}";
    }
}
