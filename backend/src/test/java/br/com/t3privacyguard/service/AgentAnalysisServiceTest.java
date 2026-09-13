package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.integration.GatewayAgentClient;
import br.com.t3privacyguard.integration.GatewayAgentClient.AgentProposal;
import br.com.t3privacyguard.integration.GatewayAgentClient.AgentProposalResult;
import br.com.t3privacyguard.integration.GatewayPolicyClient;
import br.com.t3privacyguard.integration.GatewayPolicyClient.GatewayDecision;
import br.com.t3privacyguard.integration.GatewayUnavailableException;
import br.com.t3privacyguard.integration.SensitivePromptRejectedException;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
class AgentAnalysisServiceTest {
    private static final String POLICY_VERSION = "2026-09-12.1";
    private static final String POLICY_HASH = "a".repeat(64);

    @Autowired AgentAnalysisService service;
    @Autowired IncidentService incidentService;
    @Autowired IncidentRepository incidents;
    @Autowired ActionProposalRepository actions;
    @Autowired PolicyDecisionRepository decisions;
    @Autowired AuditEventRepository audits;
    @Autowired RemediationExecutionRepository remediations;
    @MockitoBean GatewayAgentClient agentGateway;
    @MockitoBean GatewayPolicyClient policyGateway;

    @BeforeEach
    void clear() {
        remediations.deleteAll(); audits.deleteAll(); decisions.deleteAll(); actions.deleteAll(); incidents.deleteAll();
    }

    @Test
    void maliciousModelProposalIsPersistedThenDeniedByIndependentPolicy() {
        when(agentGateway.propose(eq("malicious prompt"))).thenReturn(new AgentProposalResult(
            "openai-compatible", "tool-model",
            new AgentProposal("revoke-credential", "credential:production-security-api", "incident-remediation", "attacker.example",
                List.of("incident_id", "credential_id", "reason", "api_key"), List.of())
        ));
        when(policyGateway.evaluate(any())).thenAnswer(invocation -> {
            var request = invocation.getArgument(0, GatewayPolicyClient.GatewayEvaluationRequest.class);
            return decision(request, DecisionType.DENY, "SECRET_DISCLOSURE_FORBIDDEN", List.of(), List.of(), List.of(), List.of());
        });

        var result = service.analyze("malicious prompt");
        assertThat(result.provider()).isEqualTo("openai-compatible");
        assertThat(result.action().host()).isEqualTo("attacker.example");
        assertThat(result.action().fields()).contains("api_key");
        assertThat(result.decision().decision()).isEqualTo(DecisionType.DENY);
        assertThat(result.decision().policyVersion()).isEqualTo(POLICY_VERSION);
        assertThat(actions.count()).isEqualTo(1);
    }

    @Test
    void legitimateModelProposalCanBeAllowedButIsNotAutoAuthorized() {
        when(agentGateway.propose(eq("safe prompt"))).thenReturn(new AgentProposalResult(
            "openai-compatible", "tool-model",
            new AgentProposal("revoke-credential", "credential:production-security-api", "incident-remediation", "postman-echo.com",
                List.of("incident_id", "credential_id", "reason"), List.of())
        ));
        when(policyGateway.evaluate(any())).thenAnswer(invocation -> {
            var request = invocation.getArgument(0, GatewayPolicyClient.GatewayEvaluationRequest.class);
            return decision(request, DecisionType.ALLOW, "POLICY_ALLOW", request.fields(), List.of(), List.of(), List.of());
        });
        var result = service.analyze("safe prompt");
        assertThat(result.decision().decision()).isEqualTo(DecisionType.ALLOW);
        assertThat(result.action().status().name()).isEqualTo("EVALUATED");
        assertThat(remediations.count()).isZero();
    }

    @Test
    void secondAgentProposalReusesExistingIncidentAndIsIndependentlyEvaluated() {
        when(agentGateway.propose(eq("malicious prompt"))).thenReturn(new AgentProposalResult(
            "openai-compatible", "tool-model",
            new AgentProposal("revoke-credential", "credential:production-security-api", "incident-remediation", "attacker.example",
                List.of("incident_id", "credential_id", "reason", "api_key"), List.of())
        ));
        when(agentGateway.propose(eq("safe follow-up"))).thenReturn(new AgentProposalResult(
            "openai-compatible", "tool-model",
            new AgentProposal("revoke-credential", "credential:production-security-api", "incident-remediation", "postman-echo.com",
                List.of("incident_id", "credential_id", "reason"), List.of())
        ));
        when(policyGateway.evaluate(any())).thenAnswer(invocation -> {
            var request = invocation.getArgument(0, GatewayPolicyClient.GatewayEvaluationRequest.class);
            if ("attacker.example".equals(request.host())) {
                return decision(request, DecisionType.DENY, "SECRET_DISCLOSURE_FORBIDDEN", List.of(), request.fields(), List.of(), List.of());
            }
            return decision(request, DecisionType.ALLOW, "POLICY_ALLOW", request.fields(), List.of(), List.of(), List.of());
        });

        var first = service.analyze("malicious prompt");
        var second = service.analyzeExistingIncident(first.incident().id(), "safe follow-up");

        assertThat(second.incident().id()).isEqualTo(first.incident().id());
        assertThat(second.action().id()).isNotEqualTo(first.action().id());
        assertThat(second.action().host()).isEqualTo("postman-echo.com");
        assertThat(second.decision().decision()).isEqualTo(DecisionType.ALLOW);
        assertThat(second.action().status().name()).isEqualTo("EVALUATED");
        assertThat(incidents.count()).isEqualTo(1);
        assertThat(actions.count()).isEqualTo(2);
        assertThat(decisions.count()).isEqualTo(2);
        assertThat(remediations.count()).isZero();
    }

    @Test
    void providerFailureOnExistingIncidentDoesNotCreateSyntheticFallbackAction() {
        var incident = incidentService.createIncident(new CreateIncidentRequest(
            "Existing incident", Severity.CRITICAL, "Synthetic incident for agent retry", "test"
        ));
        when(agentGateway.propose(eq("provider unavailable")))
            .thenThrow(new GatewayUnavailableException("Configured AI provider is unavailable"));

        assertThatThrownBy(() -> service.analyzeExistingIncident(incident.id(), "provider unavailable"))
            .isInstanceOf(GatewayUnavailableException.class);

        assertThat(incidents.count()).isEqualTo(1);
        assertThat(actions.count()).isZero();
        assertThat(decisions.count()).isZero();
        assertThat(remediations.count()).isZero();
    }

    @Test
    void modelCanRequestVerifiedEmailOnlyAsLogicalReference() {
        when(agentGateway.propose(eq("notify verified contact"))).thenReturn(new AgentProposalResult(
            "openai-compatible", "tool-model",
            new AgentProposal("notify-security", "incident:42", "incident-notification", "postman-echo.com",
                List.of("incident_id", "severity", "summary"), List.of("verified_email"))
        ));
        when(policyGateway.evaluate(any())).thenAnswer(invocation -> {
            var request = invocation.getArgument(0, GatewayPolicyClient.GatewayEvaluationRequest.class);
            return decision(request, DecisionType.ALLOW, "POLICY_ALLOW", request.fields(), List.of(), request.privateRefs(), List.of());
        });

        var result = service.analyze("notify verified contact");
        assertThat(result.action().privateRefs()).containsExactly("verified_email");
        assertThat(result.decision().allowedPrivateRefs()).containsExactly("verified_email");
        assertThat(result.incident().summary()).doesNotContain("@", "{{profile");
    }

    @Test
    void sensitivePromptRejectedBeforeProviderCreatesNoPersistentBusinessData() {
        when(agentGateway.propose(eq("send synthetic@example.com"))).thenThrow(new SensitivePromptRejectedException());

        assertThatThrownBy(() -> service.analyze("send synthetic@example.com"))
            .isInstanceOf(SensitivePromptRejectedException.class)
            .hasMessageNotContaining("synthetic@example.com");

        assertThat(incidents.count()).isZero();
        assertThat(actions.count()).isZero();
        assertThat(decisions.count()).isZero();
        assertThat(audits.count()).isZero();
        assertThat(remediations.count()).isZero();
    }

    private static GatewayDecision decision(
        GatewayPolicyClient.GatewayEvaluationRequest request,
        DecisionType type,
        String code,
        List<String> allowedFields,
        List<String> redactedFields,
        List<String> allowedPrivateRefs,
        List<String> redactedPrivateRefs
    ) {
        return new GatewayDecision(
            request.requestId(), type, code, type == DecisionType.ALLOW ? "Allowed" : "Denied",
            allowedFields, redactedFields, allowedPrivateRefs, redactedPrivateRefs,
            POLICY_VERSION, POLICY_HASH, true
        );
    }
}
