package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentRegistrationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ContractIdentity;
import br.com.t3privacyguard.integration.GatewaySystemClient.DelegationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ExecutorStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.TenantStatus;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SystemStatusServiceTest {
    @Mock GatewaySystemClient gateway;
    @InjectMocks SystemStatusService service;

    @BeforeEach
    void baseStatus() {
        when(gateway.health()).thenReturn(true);
        when(gateway.tenantStatus()).thenReturn(Optional.of(new TenantStatus(true, true, "did:t3n:tenant", "testnet")));
        when(gateway.agentStatus()).thenReturn(Optional.of(new AgentStatus(true, true, true, "did:t3n:proposal-agent", "testnet")));
        when(gateway.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, true, true, "did:t3n:protected-executor", "testnet")));
        when(gateway.agentRegistration()).thenReturn(Optional.of(new AgentRegistrationStatus(
            "did:t3n:proposal-agent", "REGISTERED", "https://node.example/api/agent-card/did:t3n:proposal-agent", "a".repeat(64), "2026-09-12T20:00:00Z", List.of("DID")
        )));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("z:tenant:privacy-guard", "0.4.0")));
    }

    private static DelegationStatus proposal(String memberState, String effectiveState) {
        return new DelegationStatus(
            memberState, effectiveState,
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        );
    }

    private static DelegationStatus executor(String memberState, String effectiveState) {
        return new DelegationStatus(
            memberState, effectiveState,
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason"), List.of("security.example", "verification.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        );
    }

    @Test
    void reportsProposalAndProtectedExecutorSeparatelyWithEffectiveAccess() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(proposal("ACTIVE", "ACTIVE")));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.tenantAuthenticated()).isTrue();
        assertThat(result.agentAuthenticated()).isTrue();
        assertThat(result.agentDid()).isEqualTo("did:t3n:proposal-agent");
        assertThat(result.executorAuthenticated()).isTrue();
        assertThat(result.executorDid()).isEqualTo("did:t3n:protected-executor");
        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.delegationState()).isEqualTo("ACTIVE");
        assertThat(result.delegationEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.delegatedFunctions()).containsExactly("evaluate-action");
        assertThat(result.delegatedScopes()).containsExactly("incident_id", "credential_id", "reason");
        assertThat(result.delegationCheckedFunctions()).containsExactly("evaluate-action");
        assertThat(result.executorDelegationState()).isEqualTo("ACTIVE");
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.executorDelegationCheckedFunctions()).containsExactly("execute-remediation", "verify-remediation");
        assertThat(result.message()).contains("effective Proposal").contains("Protected Executor");
    }

    @Test
    void proposalEffectiveDenialFailsEvaluationAndProtectedReadiness() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(proposal("ACTIVE", "DENIED")));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.delegationEffectiveState()).isEqualTo("DENIED");
        assertThat(result.message()).contains("effective T3N access is denied");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void proposalUnknownEffectiveAccessFailsClosed() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(proposal("ACTIVE", "UNKNOWN")));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.message()).contains("could not be confirmed for policy evaluation");
    }

    @Test
    void executorEffectiveDenialKeepsEvaluationReadyButBlocksProtectedRemediation() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(proposal("ACTIVE", "ACTIVE")));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(executor("ACTIVE", "DENIED")));

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("DENIED");
        assertThat(result.message()).contains("Policy evaluation is ready").contains("denied for the Protected Executor");
    }

    @Test
    void executorUnavailableFailsProtectedReadinessEvenWhenProposalAgentIsAuthorized() {
        when(gateway.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, false, false, null, "testnet")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(proposal("ACTIVE", "ACTIVE")));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.empty());

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.executorDelegationState()).isEqualTo("UNKNOWN");
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("UNKNOWN");
    }

    @Test
    void registrationDidMismatchDoesNotReclassifyEffectiveDelegations() {
        when(gateway.agentRegistration()).thenReturn(Optional.of(new AgentRegistrationStatus("did:t3n:other", "REGISTERED", "https://node.example/card", "a".repeat(64), "2026-09-12T20:00:00Z", List.of("DID"))));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(proposal("ACTIVE", "ACTIVE")));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.agentRegistrationState()).isEqualTo("MISMATCH");
        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.message()).contains("controls are ready").contains("onboarding is not confirmed");
    }

    @Test
    void unknownProposalDelegationNeverBecomesReadyMessage() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.empty());
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.delegationState()).isEqualTo("UNKNOWN");
        assertThat(result.delegationEffectiveState()).isEqualTo("UNKNOWN");
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void scheduledProposalDelegationNeverBecomesReady() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(proposal("SCHEDULED", "DENIED")));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.delegationState()).isEqualTo("SCHEDULED");
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.message()).isEqualTo("Proposal Member Delegation exists, but its authorization window has not begun.");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void scheduledExecutorDelegationNeverBecomesReady() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(proposal("ACTIVE", "ACTIVE")));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(executor("SCHEDULED", "DENIED")));

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.executorDelegationState()).isEqualTo("SCHEDULED");
        assertThat(result.message()).isEqualTo("Executor Member Delegation exists, but its authorization window has not begun.");
        assertThat(result.message()).doesNotContain("controls are ready");
    }
}