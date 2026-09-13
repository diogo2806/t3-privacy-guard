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
        when(gateway.agentRegistration()).thenReturn(Optional.of(registration("did:t3n:proposal-agent", "REGISTERED")));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("z:tenant:privacy-guard", "0.4.0")));
    }

    @Test
    void reportsMemberGrantAndEffectiveAccessSeparatelyForBothPrincipals() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of()
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id"), List.of("security.example", "verification.example")
        )));

        var result = service.status();

        assertThat(result.tenantAuthenticated()).isTrue();
        assertThat(result.agentAuthenticated()).isTrue();
        assertThat(result.agentDid()).isEqualTo("did:t3n:proposal-agent");
        assertThat(result.executorAuthenticated()).isTrue();
        assertThat(result.executorDid()).isEqualTo("did:t3n:protected-executor");
        assertThat(result.agentRegistrationState()).isEqualTo("REGISTERED");
        assertThat(result.agentCardServices()).containsExactly("A2A", "DID");
        assertThat(result.a2aConfigured()).isTrue();
        assertThat(result.a2aPublicUrl()).isEqualTo("https://guard.example/a2a");
        assertThat(result.a2aConfigurationCheckedAt()).isEqualTo("2026-09-13T11:00:00Z");
        assertThat(result.contractResolved()).isTrue();
        assertThat(result.delegationMemberState()).isEqualTo("ACTIVE");
        assertThat(result.delegationEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.delegatedFunctions()).containsExactly("evaluate-action");
        assertThat(result.delegatedScopes()).containsExactly("incident_id");
        assertThat(result.executorDelegationMemberState()).isEqualTo("ACTIVE");
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.executorDelegatedFunctions()).containsExactly("execute-remediation", "verify-remediation");
        assertThat(result.executorAllowedHosts()).containsExactly("security.example", "verification.example");
        assertThat(result.message()).contains("effective least-privilege access");
    }

    @Test
    void memberGrantAloneNeverMakesControlsReadyWhenPlatformRejectsProposalAgent() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "INCOMPLETE", List.of("evaluate-action"), List.of("incident_id"), List.of()
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example")
        )));

        var result = service.status();

        assertThat(result.delegationMemberState()).isEqualTo("ACTIVE");
        assertThat(result.delegationEffectiveState()).isEqualTo("INCOMPLETE");
        assertThat(result.message()).contains("did not authorize effective access");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void unknownEffectiveVerdictNeverBecomesReady() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "UNKNOWN", List.of("evaluate-action"), List.of("incident_id"), List.of()
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example")
        )));

        var result = service.status();

        assertThat(result.delegationEffectiveState()).isEqualTo("UNKNOWN");
        assertThat(result.message()).contains("effective delegation verdict is unavailable");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void executorUnavailableFailsReadinessEvenWhenProposalAgentHasEffectiveAccess() {
        when(gateway.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, false, false, null, "testnet")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of()
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.empty());

        var result = service.status();

        assertThat(result.agentAuthenticated()).isTrue();
        assertThat(result.executorAuthenticated()).isFalse();
        assertThat(result.delegationEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("UNKNOWN");
        assertThat(result.message()).contains("not confirmed as ready");
    }

    @Test
    void registrationDidMismatchDoesNotReclassifyConfirmedEffectiveAccess() {
        when(gateway.agentRegistration()).thenReturn(Optional.of(registration("did:t3n:other", "REGISTERED")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of()
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example")
        )));

        var result = service.status();

        assertThat(result.agentRegistrationState()).isEqualTo("MISMATCH");
        assertThat(result.delegationEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.message()).contains("controls are ready").contains("onboarding is not confirmed");
    }

    @Test
    void scheduledProposalMemberGrantNeverBecomesReady() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "SCHEDULED", "INCOMPLETE", List.of("evaluate-action"), List.of("incident_id"), List.of()
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example")
        )));

        var result = service.status();

        assertThat(result.delegationMemberState()).isEqualTo("SCHEDULED");
        assertThat(result.delegationEffectiveState()).isEqualTo("INCOMPLETE");
        assertThat(result.message()).contains("authorization window has not begun");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void scheduledExecutorMemberGrantNeverBecomesReady() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of()
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "SCHEDULED", "INCOMPLETE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example")
        )));

        var result = service.status();

        assertThat(result.executorDelegationMemberState()).isEqualTo("SCHEDULED");
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("INCOMPLETE");
        assertThat(result.message()).contains("authorization window has not begun");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    private static AgentRegistrationStatus registration(String did, String state) {
        return new AgentRegistrationStatus(
            did,
            state,
            "https://node.example/api/agent-card/" + did,
            "a".repeat(64),
            "2026-09-13T11:00:00Z",
            List.of("A2A", "DID"),
            true,
            "https://guard.example/a2a",
            "2026-09-13T11:00:00Z"
        );
    }

    private static DelegationStatus delegation(String memberState, String effectiveState, List<String> functions, List<String> scopes, List<String> allowedHosts) {
        return new DelegationStatus(memberState, effectiveState, functions, scopes, allowedHosts, List.of("member_delegation"), List.of());
    }
}
