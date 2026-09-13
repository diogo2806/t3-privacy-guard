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

    @Test
    void reportsProposalAndProtectedExecutorSeparately() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(new DelegationStatus(
            "ACTIVE", List.of("evaluate-action"), List.of()
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(new DelegationStatus(
            "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("security.example", "verification.example")
        )));

        var result = service.status();

        assertThat(result.tenantAuthenticated()).isTrue();
        assertThat(result.agentAuthenticated()).isTrue();
        assertThat(result.agentDid()).isEqualTo("did:t3n:proposal-agent");
        assertThat(result.executorAuthenticated()).isTrue();
        assertThat(result.executorDid()).isEqualTo("did:t3n:protected-executor");
        assertThat(result.agentRegistrationState()).isEqualTo("REGISTERED");
        assertThat(result.contractResolved()).isTrue();
        assertThat(result.delegationState()).isEqualTo("ACTIVE");
        assertThat(result.delegatedFunctions()).containsExactly("evaluate-action");
        assertThat(result.allowedHosts()).isEmpty();
        assertThat(result.executorDelegationState()).isEqualTo("ACTIVE");
        assertThat(result.executorDelegatedFunctions()).containsExactly("execute-remediation", "verify-remediation");
        assertThat(result.executorAllowedHosts()).containsExactly("security.example", "verification.example");
        assertThat(result.message()).contains("proposal agent").contains("protected executor");
    }

    @Test
    void executorUnavailableFailsReadinessEvenWhenProposalAgentIsAuthorized() {
        when(gateway.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, false, false, null, "testnet")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(new DelegationStatus("ACTIVE", List.of("evaluate-action"), List.of())));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.empty());

        var result = service.status();

        assertThat(result.agentAuthenticated()).isTrue();
        assertThat(result.executorAuthenticated()).isFalse();
        assertThat(result.delegationState()).isEqualTo("ACTIVE");
        assertThat(result.executorDelegationState()).isEqualTo("UNKNOWN");
        assertThat(result.message()).contains("not confirmed as ready");
    }

    @Test
    void registrationDidMismatchDoesNotReclassifyLeastPrivilegeDelegations() {
        when(gateway.agentRegistration()).thenReturn(Optional.of(new AgentRegistrationStatus(
            "did:t3n:other", "REGISTERED", "https://node.example/card", "a".repeat(64), "2026-09-12T20:00:00Z", List.of("DID")
        )));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(new DelegationStatus("ACTIVE", List.of("evaluate-action"), List.of())));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(new DelegationStatus("ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("security.example"))));

        var result = service.status();

        assertThat(result.agentRegistrationState()).isEqualTo("MISMATCH");
        assertThat(result.delegationState()).isEqualTo("ACTIVE");
        assertThat(result.executorDelegationState()).isEqualTo("ACTIVE");
        assertThat(result.message()).contains("controls are ready").contains("onboarding is not confirmed");
    }

    @Test
    void unknownProposalDelegationNeverBecomesReadyMessage() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.empty());
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(new DelegationStatus("ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("security.example"))));

        var result = service.status();

        assertThat(result.delegationState()).isEqualTo("UNKNOWN");
        assertThat(result.executorDelegationState()).isEqualTo("ACTIVE");
        assertThat(result.message()).contains("not confirmed as ready");
    }
}
