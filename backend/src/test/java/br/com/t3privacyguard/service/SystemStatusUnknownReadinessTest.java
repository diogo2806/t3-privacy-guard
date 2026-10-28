package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.integration.RuntimeStatusClient;
import br.com.t3privacyguard.integration.RuntimeStatusClient.AgentStatus;
import br.com.t3privacyguard.integration.RuntimeStatusClient.ContractIdentity;
import br.com.t3privacyguard.integration.RuntimeStatusClient.DelegationStatus;
import br.com.t3privacyguard.integration.RuntimeStatusClient.EnterpriseIntegrationReadiness;
import br.com.t3privacyguard.integration.RuntimeStatusClient.ExecutorStatus;
import br.com.t3privacyguard.integration.RuntimeStatusClient.TenantStatus;
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

    @Mock RuntimeStatusClient runtime;
    @Mock SecurityRemediationCredential remediationCredential;
    @InjectMocks SystemStatusService service;

    @BeforeEach
    void baseStatus() {
        when(runtime.health()).thenReturn(true);
        when(runtime.tenantStatus()).thenReturn(Optional.of(new TenantStatus(true, true, "agent:tenant", "selfhosted")));
        when(runtime.agentStatus()).thenReturn(Optional.of(new AgentStatus(true, true, true, "agent:proposal-agent", "selfhosted")));
        when(runtime.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, true, true, "agent:executor", "selfhosted")));
        when(runtime.contractIdentity()).thenReturn(Optional.of(new ContractIdentity(CONTRACT_ID, "0.4.1")));
    }

    @Test
    void preservesUnknownEnterpriseFactsInsteadOfConvertingThemToFalse() {
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.of(unknownIntegration()));
        when(runtime.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));
        when(runtime.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));

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
    void diagnosticCodesFromOtherRuntimesNormalizeToRuntimeUnavailable() {
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.of(unknownIntegration("INSUFFICIENT_CREDIT")));
        when(runtime.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));
        when(runtime.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));

        var result = service.status();

        assertThat(result.enterpriseIntegrationState()).isEqualTo("UNKNOWN");
        assertThat(result.enterpriseIntegrationDiagnosticCode()).isEqualTo("TRUST_RUNTIME_UNAVAILABLE");
        assertThat(result.enterpriseIntegrationReady()).isFalse();
        assertThat(result.enterpriseExecutionConfigured()).isNull();
        assertThat(result.enterpriseCredentialConfigured()).isNull();
    }

    @Test
    void missingEnterpriseReadinessAlsoRemainsUnknownAndFailClosed() {
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.empty());
        when(runtime.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));
        when(runtime.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));

        var result = service.status();

        assertThat(result.enterpriseIntegrationState()).isEqualTo("UNKNOWN");
        assertThat(result.enterpriseIntegrationDiagnosticCode()).isEqualTo("TRUST_RUNTIME_UNAVAILABLE");
        assertThat(result.enterpriseExecutionConfigured()).isNull();
        assertThat(result.enterprisePolicyAllowsExecutionHost()).isNull();
    }

    @Test
    void unknownProposalMemberStateUsesInconclusiveCopyAndFailsClosed() {
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.of(unknownIntegration()));
        when(runtime.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(delegation("UNKNOWN", "UNKNOWN")));
        when(runtime.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));

        var result = service.status();

        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.message()).isEqualTo("The proposal agent's grant could not be confirmed; policy evaluation remains unavailable.");
    }

    @Test
    void notGrantedAndRevokedProposalStatesRemainExplicit() {
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.of(unknownIntegration()));
        when(runtime.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(activeDelegation()));

        when(runtime.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(delegation("NOT_GRANTED", "UNKNOWN")));
        assertThat(service.status().message()).isEqualTo("guard-runtime does not recognize the proposal agent credential; policy evaluation is not ready.");

        when(runtime.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(delegation("REVOKED", "UNKNOWN")));
        assertThat(service.status().message()).isEqualTo("guard-runtime does not recognize the proposal agent credential; policy evaluation is not ready.");
    }

    private static EnterpriseIntegrationReadiness unknownIntegration() {
        return unknownIntegration("TRUST_RUNTIME_UNAVAILABLE");
    }

    private static EnterpriseIntegrationReadiness unknownIntegration(String diagnosticCode) {
        return new EnterpriseIntegrationReadiness(
            "UNKNOWN",
            diagnosticCode,
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
