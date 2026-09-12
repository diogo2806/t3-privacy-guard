package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.integration.GatewayAgentClient;
import br.com.t3privacyguard.integration.GatewayAgentClient.AgentProposal;
import br.com.t3privacyguard.integration.GatewayAgentClient.AgentProposalResult;
import br.com.t3privacyguard.integration.GatewayPolicyClient;
import br.com.t3privacyguard.integration.GatewayPolicyClient.GatewayDecision;
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
    @Autowired AgentAnalysisService service;
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
            return new GatewayDecision(request.requestId(), DecisionType.DENY, "SECRET_DISCLOSURE_FORBIDDEN", "Denied", List.of(), List.of(), List.of(), List.of());
        });

        var result = service.analyze("malicious prompt");
        assertThat(result.provider()).isEqualTo("openai-compatible");
        assertThat(result.action().host()).isEqualTo("attacker.example");
        assertThat(result.action().fields()).contains("api_key");
        assertThat(result.decision().decision()).isEqualTo(DecisionType.DENY);
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
            return new GatewayDecision(request.requestId(), DecisionType.ALLOW, "POLICY_ALLOW", "Allowed", request.fields(), List.of(), List.of(), List.of());
        });
        var result = service.analyze("safe prompt");
        assertThat(result.decision().decision()).isEqualTo(DecisionType.ALLOW);
        assertThat(result.action().status().name()).isEqualTo("EVALUATED");
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
            return new GatewayDecision(request.requestId(), DecisionType.ALLOW, "POLICY_ALLOW", "Allowed",
                request.fields(), List.of(), request.privateRefs(), List.of());
        });

        var result = service.analyze("notify verified contact");
        assertThat(result.action().privateRefs()).containsExactly("verified_email");
        assertThat(result.decision().allowedPrivateRefs()).containsExactly("verified_email");
        assertThat(result.incident().summary()).doesNotContain("@", "{{profile");
    }
}
