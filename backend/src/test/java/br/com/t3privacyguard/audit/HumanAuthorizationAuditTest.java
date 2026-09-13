package br.com.t3privacyguard.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.api.ApiModels.CreateActionRequest;
import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.integration.GatewayPolicyClient;
import br.com.t3privacyguard.integration.GatewayPolicyClient.GatewayDecision;
import br.com.t3privacyguard.integration.GatewayRemediationClient;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.AuditChainHeadRepository;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import br.com.t3privacyguard.service.IncidentService;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
class HumanAuthorizationAuditTest {
    private static final String POLICY_VERSION = "2026-09-12.1";
    private static final String POLICY_HASH = "a".repeat(64);

    @Autowired IncidentService service;
    @Autowired AuditIntegrityService auditIntegrity;
    @Autowired RemediationExecutionRepository remediations;
    @Autowired AuditChainHeadRepository heads;
    @Autowired AuditEventRepository audits;
    @Autowired PolicyDecisionRepository decisions;
    @Autowired ActionProposalRepository actions;
    @Autowired IncidentRepository incidents;
    @MockitoBean GatewayPolicyClient gateway;
    @MockitoBean GatewayRemediationClient remediationGateway;

    @BeforeEach
    void clear() {
        remediations.deleteAll();
        audits.deleteAll();
        heads.deleteAll();
        decisions.deleteAll();
        actions.deleteAll();
        incidents.deleteAll();
        reset(gateway, remediationGateway);
    }

    @Test
    void authorizationPrincipalIsInsideVerifiedTamperEvidentAuditChain() {
        var incident = service.createIncident(new CreateIncidentRequest(
            "Human approval", Severity.CRITICAL, "Synthetic incident", "audit-test"
        ));
        var action = service.addAction(incident.id(), new CreateActionRequest(
            "request-human-audit", "revoke-credential", "credential:test", "incident-remediation", "postman-echo.com",
            List.of("incident_id", "credential_id", "reason"), List.of()
        ));
        when(gateway.evaluate(any())).thenReturn(new GatewayDecision(
            action.requestId(), DecisionType.ALLOW, "POLICY_ALLOW", "Allowed",
            List.of("incident_id", "credential_id", "reason"), List.of(), List.of(), List.of(),
            POLICY_VERSION, POLICY_HASH, true
        ));
        service.evaluate(incident.id(), action.id());
        service.authorizeRemediation(incident.id(), action.id(), "ops-reviewer");

        AuditIntegrityService.Verification verification = auditIntegrity.verify(incident.id());

        assertThat(verification.state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(verification.events()).anySatisfy(event -> {
            assertThat(event.getType()).isEqualTo("REMEDIATION_AUTHORIZED");
            assertThat(event.getMessage()).contains("ops-reviewer");
            assertThat(event.getEventMac()).matches("[a-f0-9]{64}");
        });
    }
}
