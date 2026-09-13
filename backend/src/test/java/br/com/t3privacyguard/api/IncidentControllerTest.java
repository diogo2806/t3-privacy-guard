package br.com.t3privacyguard.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.api.ApiModels.RemediationAuthorizationResponse;
import br.com.t3privacyguard.service.AuditEvidenceService;
import br.com.t3privacyguard.service.IncidentService;
import br.com.t3privacyguard.service.RemediationQueryService;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;

class IncidentControllerTest {
    @Test
    void authorizeRemediationUsesAuthenticatedPrincipalInsteadOfClientInput() {
        IncidentService service = mock(IncidentService.class);
        RemediationQueryService remediationQuery = mock(RemediationQueryService.class);
        AuditEvidenceService auditEvidence = mock(AuditEvidenceService.class);
        Authentication authentication = mock(Authentication.class);
        IncidentController controller = new IncidentController(service, remediationQuery, auditEvidence);
        Instant authorizedAt = Instant.parse("2026-09-13T12:40:00Z");

        when(authentication.getName()).thenReturn("ops-reviewer");
        when(service.authorizeRemediation("incident-1", "action-1", "ops-reviewer"))
            .thenReturn(new RemediationAuthorizationResponse(
                "incident-1", "action-1", "request-1", "REMEDIATION_AUTHORIZED", "ops-reviewer", authorizedAt
            ));

        RemediationAuthorizationResponse response = controller.authorizeRemediation("incident-1", "action-1", authentication);

        assertThat(response.authorizedBy()).isEqualTo("ops-reviewer");
        assertThat(response.authorizedAt()).isEqualTo(authorizedAt);
        verify(service).authorizeRemediation("incident-1", "action-1", "ops-reviewer");
    }

    @Test
    void missingAuthenticationNeverSuppliesAnInventedPrincipal() {
        IncidentService service = mock(IncidentService.class);
        IncidentController controller = new IncidentController(service, mock(RemediationQueryService.class), mock(AuditEvidenceService.class));

        controller.authorizeRemediation("incident-1", "action-1", null);

        verify(service).authorizeRemediation("incident-1", "action-1", null);
    }
}
