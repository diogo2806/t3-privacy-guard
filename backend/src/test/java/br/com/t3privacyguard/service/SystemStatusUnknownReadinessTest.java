package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ContractIdentity;
import br.com.t3privacyguard.integration.GatewaySystemClient.DelegationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.EnterpriseIntegrationReadiness;
import br.com.t3privacyguard.integration.GatewaySystemClient.ExecutorStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.TenantStatus;
import br.com.t3privacyguard.security.SecurityRemediationCredential;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SystemStatusUnknownReadinessTest {
    private static final String CONTRACT_ID = "z:tenant:privacy-guard";

    @Mock GatewaySystemClient gateway;
    @Mock SecurityRemediationCredential remediationCredential;
    @InjectMocks SystemStatusService service;

    @BeforeEach
    void baseStatus() {
        when(gateway.health()).thenReturn(true);
        when(gateway.tenantStatus()).thenReturn(Optional.of(new TenantStatus(true, true, "did:t3n:tenant", "testnet")));
        when(gateway.agentStatus()).thenReturn(Optional.of(new AgentStatus(true, true, true, "did:t3n:proposal-agent", "testnet")));
        when(gateway.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, true, true, "did:t3n:executor", "testnet")));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new ContractIdentity(CONTRACT_ID, "0.4.1")));
    }

    @Test
    void preservesUnknownEnterpriseFactsInsteadOfConvertingThemToFalse() {
        when(gateway.enterpriseIntegrationReadiness()).thenReturn(Optional.of(unknownIntegration()));
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));

        var result = service.status();

        assertThat(result.enterpriseIntegrationState()).isEqualTo("UNKNOWN");
        assertThat(result.enterpriseIntegrationReady()).isFalse();
        assertThat(result.enterpriseExecutionConfigured()).isNull();
        assertThat(result.enterpriseVerificationConfigured()).isNull();
        assertThat(result.enterpriseCredentialConfigured()).isNull();
        assertThat(result.enterprisePolicyAllowsExecutionHost()).isNull();
        assertThat(result.enterprisePolicyAllowsVerificationHost()).isNull();
        assertThat(result.enterpriseExecutorDelegationAllowsExecutionHost()).isNull();
        assertThat(result.enterpriseExecutorDelegationAllowsVerificationHost()).isNull();
    }

    @Test
    void missingEnterpriseReadinessAlsoRemainsUnknownAndFailClosed() {
        when(gateway.enterpriseIntegrationReadiness()).thenReturn(Optional.empty());
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));

        var result = service.status();

        assertThat(result.enterpriseIntegrationState()).isEqualTo("UNKNOWN");
        assertThat(result.enterpriseIntegrationDiagnosticCode()).isEqualTo("T3N_CONTROL_PLANE_UNAVAILABLE");
        assertThat(result.enterpriseExecutionConfigured()).isNull();
        assertThat(result.enterprisePolicyAllowsExecutionHost()).isNull();
    }

    @Test
    void unknownProposalMemberStateUsesInconclusiveCopyAndFailsClosed() {
        when(gateway.enterpriseIntegrationReadiness()).thenReturn(Optional.of(unknownIntegration()));
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(delegation("UNKNOWN", "UNKNOWN")));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));

        var result = service.status();

        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.message()).isEqualTo("Proposal Member grant could not be confirmed; policy evaluation remains unavailable.");
    }

    @Test
    void notGrantedAndRevokedProposalStatesRemainExplicit() {
        when(gateway.enterpriseIntegrationReadiness()).thenReturn(Optional.of(unknownIntegration()));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));

        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(delegation("NOT_GRANTED", "UNKNOWN")));
        assertThat(service.status().message()).isEqualTo("Proposal Member grant has not been granted; policy evaluation is not ready.");

        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(delegation("REVOKED", "UNKNOWN")));
        assertThat(service.status().message()).isEqualTo("Proposal Member grant has been revoked; policy evaluation is not ready.");
    }

    private static EnterpriseIntegrationReadiness unknownIntegration() {
        return new EnterpriseIntegrationReadiness(
            "UNKNOWN",
            "T3N_CONTROL_PLANE_UNAVAILABLE",
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            List.of("revoke-credential", "notify-security"),
            List.of("revoke-credential", "notify-security"),
            List.of(),
            List.of(),
            "2026-09-17T12:00:00Z"
        );
    }

    private static DelegationStatus activeDelegation() {
        return delegation("ACTIVE", "ACTIVE");
    }

    private static DelegationStatus delegation(String memberState, String effectiveState) {
        return new DelegationStatus(
            memberState,
            effectiveState,
            List.of("evaluate-action"),
            List.of("incident_id"),
            List.of("security.example"),
            List.of("evaluate-action"),
            List.of("incident_id")
        );
    }
}
