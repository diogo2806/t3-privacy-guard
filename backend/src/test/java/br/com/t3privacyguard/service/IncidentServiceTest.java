package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import br.com.t3privacyguard.api.ApiModels.*;
import br.com.t3privacyguard.domain.*;
import br.com.t3privacyguard.integration.GatewayPolicyClient;
import br.com.t3privacyguard.integration.GatewayPolicyClient.GatewayDecision;
import br.com.t3privacyguard.persistence.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(properties = "spring.datasource.url=jdbc:h2:mem:incident-test;DB_CLOSE_DELAY=-1")
class IncidentServiceTest {
    @Autowired IncidentService service;
    @Autowired IncidentRepository incidents;
    @Autowired ActionProposalRepository actions;
    @Autowired PolicyDecisionRepository decisions;
    @Autowired AuditEventRepository audits;
    @MockitoBean GatewayPolicyClient gateway;

    @BeforeEach
    void clear() {
        audits.deleteAll();
        decisions.deleteAll();
        actions.deleteAll();
        incidents.deleteAll();
        reset(gateway);
    }

    @Test
    void rejectsDuplicateRequestIdAsReplay() {
        var incident = service.createIncident(new CreateIncidentRequest("Leak", Severity.CRITICAL, "Synthetic incident", "test"));
        var input = new CreateActionRequest("req-1", "revoke-credential", "credential:test", "incident-remediation", "security-api.internal", List.of("incident_id", "credential_id", "reason"));
        service.addAction(incident.id(), input);
        assertThatThrownBy(() -> service.addAction(incident.id(), input)).isInstanceOf(ConflictException.class);
    }

    @Test
    void denyCannotAuthorizeRemediation() {
        var incident = service.createIncident(new CreateIncidentRequest("Attack", Severity.CRITICAL, "Synthetic incident", "test"));
        var action = service.addAction(incident.id(), new CreateActionRequest("req-2", "revoke-credential", "credential:test", "incident-remediation", "security-api.internal", List.of("incident_id", "credential_id")));
        when(gateway.evaluate(any())).thenReturn(new GatewayDecision("req-2", DecisionType.DENY, "HOST_NOT_ALLOWED", "Denied", List.of(), List.of()));
        service.evaluate(incident.id(), action.id());
        assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id())).isInstanceOf(PolicyDeniedException.class);
    }

    @Test
    void persistedDecisionPreventsSecondGatewayExecution() {
        var incident = service.createIncident(new CreateIncidentRequest("Attack", Severity.HIGH, "Synthetic incident", "test"));
        var action = service.addAction(incident.id(), new CreateActionRequest("req-3", "create-incident", "incident:test", "incident-recording", null, List.of("incident_id", "severity", "summary")));
        when(gateway.evaluate(any())).thenReturn(new GatewayDecision("req-3", DecisionType.ALLOW, "POLICY_ALLOW", "Allowed", List.of("incident_id"), List.of()));
        service.evaluate(incident.id(), action.id());
        service.evaluate(incident.id(), action.id());
        verify(gateway, times(1)).evaluate(any());
    }
}
