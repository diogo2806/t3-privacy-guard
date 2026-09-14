package br.com.t3privacyguard.api;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.api.ApiModels.RemediationAuthorizationResponse;
import br.com.t3privacyguard.security.HumanSeparationOfDutiesService;
import br.com.t3privacyguard.service.AgentAnalysisService;
import br.com.t3privacyguard.service.AuditEvidenceService;
import br.com.t3privacyguard.service.IncidentService;
import br.com.t3privacyguard.service.RemediationQueryService;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

@ExtendWith(MockitoExtension.class)
class IncidentControllerTest {
    @Mock IncidentService service;
    @Mock AgentAnalysisService agentAnalysis;
    @Mock RemediationQueryService remediationQuery;
    @Mock AuditEvidenceService auditEvidence;
    @Mock HumanSeparationOfDutiesService separationOfDuties;
    @Mock Authentication authentication;

    private IncidentController controller;

    @BeforeEach
    void setUp() {
        controller = new IncidentController(service, agentAnalysis, remediationQuery, auditEvidence, separationOfDuties);
    }

    @Test
    void remediationAuthorizationUsesAuthenticatedPrincipalInsteadOfRequestData() {
        Instant authorizedAt = Instant.parse("2026-09-13T20:00:00Z");
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("ops-reviewer");
        when(service.authorizeRemediation("incident-1", "action-1", "ops-reviewer"))
            .thenReturn(new RemediationAuthorizationResponse(
                "incident-1", "action-1", "request-1", "REMEDIATION_AUTHORIZED", "ops-reviewer", authorizedAt
            ));

        controller.authorizeRemediation("incident-1", "action-1", authentication);

        verify(service).authorizeRemediation("incident-1", "action-1", "ops-reviewer");
    }

    @Test
    void remediationAuthorizationFailsClosedWithoutAuthenticatedPrincipal() {
        when(authentication.isAuthenticated()).thenReturn(false);

        assertThatThrownBy(() -> controller.authorizeRemediation("incident-1", "action-1", authentication))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Authenticated operator principal");
        verifyNoInteractions(service);
    }

    @Test
    void remediationAuthorizationFailsClosedForBlankAuthenticatedPrincipal() {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getName()).thenReturn("   ");

        assertThatThrownBy(() -> controller.authorizeRemediation("incident-1", "action-1", authentication))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Authenticated operator principal");
        verifyNoInteractions(service);
    }

    @Test
    void executeRemediationRequiresSeparationOfDutiesBeforeProtectedOperation() {
        controller.executeRemediation("incident-1", "action-1", authentication);

        InOrder order = inOrder(separationOfDuties, service);
        order.verify(separationOfDuties).requireExecutorPrincipal("incident-1", "action-1", authentication);
        order.verify(service).executeRemediation("incident-1", "action-1");
    }

    @Test
    void verifyRemediationRequiresSeparationOfDutiesBeforeProtectedOperation() {
        controller.verifyRemediation("incident-1", "action-1", authentication);

        InOrder order = inOrder(separationOfDuties, service);
        order.verify(separationOfDuties).requireExecutorPrincipal("incident-1", "action-1", authentication);
        order.verify(service).verifyRemediation("incident-1", "action-1");
    }
}
