package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ContractIdentity;
import br.com.t3privacyguard.integration.GatewaySystemClient.DelegationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.TenantStatus;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SystemStatusServiceTest {
    @Mock GatewaySystemClient gateway;
    @InjectMocks SystemStatusService service;

    private AgentStatus registeredAgent() {
        return new AgentStatus(
            true, true, true, "did:t3n:agent", "testnet", "REGISTERED",
            "https://testnet.t3n.io/api/agent-card/did%3At3n%3Aagent", "a".repeat(64),
            "2026-09-12T22:00:00Z", List.of("DID")
        );
    }

    @Test
    void reportsObservedContractDelegationAndRegistrationSeparately() {
        when(gateway.health()).thenReturn(true);
        when(gateway.tenantStatus()).thenReturn(Optional.of(new TenantStatus(true, true, "did:t3n:tenant", "testnet")));
        when(gateway.agentStatus()).thenReturn(Optional.of(registeredAgent()));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("z:tenant:privacy-guard", "0.2.0")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(new DelegationStatus(
            "ACTIVE",
            List.of("evaluate-action", "execute-remediation"),
            List.of("postman-echo.com")
        )));

        var result = service.status();

        assertThat(result.tenantAuthenticated()).isTrue();
        assertThat(result.agentAuthenticated()).isTrue();
        assertThat(result.agentRegistrationState()).isEqualTo("REGISTERED");
        assertThat(result.agentCardServices()).containsExactly("DID");
        assertThat(result.contractResolved()).isTrue();
        assertThat(result.delegationState()).isEqualTo("ACTIVE");
        assertThat(result.delegatedFunctions()).containsExactly("evaluate-action", "execute-remediation");
        assertThat(result.allowedHosts()).containsExactly("postman-echo.com");
    }

    @Test
    void operationalAuthorizationDoesNotPretendMissingOnboardingIsRegistered() {
        when(gateway.health()).thenReturn(true);
        when(gateway.tenantStatus()).thenReturn(Optional.of(new TenantStatus(true, true, "did:t3n:tenant", "testnet")));
        when(gateway.agentStatus()).thenReturn(Optional.of(new AgentStatus(
            true, true, true, "did:t3n:agent", "testnet", "NOT_REGISTERED", null, null,
            "2026-09-12T22:00:00Z", List.of()
        )));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("z:tenant:privacy-guard", "0.2.0")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(new DelegationStatus("ACTIVE", List.of(), List.of())));

        var result = service.status();

        assertThat(result.delegationState()).isEqualTo("ACTIVE");
        assertThat(result.agentRegistrationState()).isEqualTo("NOT_REGISTERED");
        assertThat(result.message()).contains("onboarding is not confirmed as registered");
    }

    @Test
    void unknownDelegationNeverBecomesReadyMessage() {
        when(gateway.health()).thenReturn(true);
        when(gateway.tenantStatus()).thenReturn(Optional.of(new TenantStatus(true, true, "did:t3n:tenant", "testnet")));
        when(gateway.agentStatus()).thenReturn(Optional.of(registeredAgent()));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("z:tenant:privacy-guard", "0.2.0")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.empty());

        var result = service.status();

        assertThat(result.delegationState()).isEqualTo("UNKNOWN");
        assertThat(result.message()).contains("not confirmed as ready");
    }
}
