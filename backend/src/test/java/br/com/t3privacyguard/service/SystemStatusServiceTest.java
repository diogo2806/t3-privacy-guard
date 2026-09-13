package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentRegistrationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ContractIdentity;
import br.com.t3privacyguard.integration.GatewaySystemClient.DelegationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.EnterpriseIntegrationReadiness;
import br.com.t3privacyguard.integration.GatewaySystemClient.EnterpriseVerificationContract;
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
        when(gateway.enterpriseIntegrationReadiness()).thenReturn(Optional.of(integration("READY")));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("z:tenant:privacy-guard", "0.4.0")));
    }

    @Test
    void reportsIndependentEffectiveReadinessAndKeepsA2aStatus() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id"), List.of("security.example", "verification.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.enterpriseIntegrationState()).isEqualTo("READY");
        assertThat(result.enterpriseIntegrationReady()).isTrue();
        assertThat(result.enterpriseExecutionHost()).isEqualTo("security.example");
        assertThat(result.enterpriseVerificationHost()).isEqualTo("verification.example");
        assertThat(result.enterpriseVerificationContracts()).containsExactly(new EnterpriseVerificationContract("revoke-credential", "REVOKED"));
        assertThat(result.enterpriseEvaluationOnlyActions()).containsExactly("create-incident", "isolate-account", "notify-security");
        assertThat(result.delegationMemberState()).isEqualTo("ACTIVE");
        assertThat(result.delegationEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.delegationCheckedFunctions()).containsExactly("evaluate-action");
        assertThat(result.delegationCheckedScopes()).containsExactly("incident_id", "credential_id", "reason");
        assertThat(result.executorDelegationCheckedFunctions()).containsExactly("execute-remediation", "verify-remediation");
        assertThat(result.executorDelegationCheckedScopes()).containsExactly("incident_id", "credential_id", "reason");
        assertThat(result.agentCardServices()).containsExactly("A2A", "DID");
        assertThat(result.a2aConfigured()).isTrue();
        assertThat(result.a2aPublicUrl()).isEqualTo("https://guard.example/a2a");
        assertThat(result.a2aConfigurationCheckedAt()).isEqualTo("2026-09-13T11:00:00Z");
        assertThat(result.message()).contains("exact least-privilege functions/scopes");
    }

    @Test
    void enterpriseMismatchDoesNotRedefineT3nProtectedRemediationReadiness() {
        when(gateway.enterpriseIntegrationReadiness()).thenReturn(Optional.of(integration("MISMATCH")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.enterpriseIntegrationState()).isEqualTo("MISMATCH");
        assertThat(result.enterpriseIntegrationReady()).isFalse();
    }

    @Test
    void unavailableEnterpriseReadinessFailsClosedWithoutChangingT3nReadiness() {
        when(gateway.enterpriseIntegrationReadiness()).thenReturn(Optional.empty());
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.enterpriseIntegrationState()).isEqualTo("UNKNOWN");
        assertThat(result.enterpriseIntegrationReady()).isFalse();
        assertThat(result.enterpriseExecutionHost()).isNull();
        assertThat(result.enterpriseSupportedVerifiedActions()).isEmpty();
    }

    @Test
    void keepsA2aConfigurationVisibleWhenProposalAgentSessionIsUnavailable() {
        when(gateway.agentStatus()).thenReturn(Optional.of(new AgentStatus(true, false, false, null, "testnet")));
        when(gateway.agentRegistration()).thenReturn(Optional.of(registration("", "UNAVAILABLE")));

        var result = service.status();

        assertThat(result.agentAuthenticated()).isFalse();
        assertThat(result.agentRegistrationState()).isEqualTo("UNAVAILABLE");
        assertThat(result.a2aConfigured()).isTrue();
        assertThat(result.a2aPublicUrl()).isEqualTo("https://guard.example/a2a");
        assertThat(result.a2aConfigurationCheckedAt()).isEqualTo("2026-09-13T11:00:00Z");
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
    }

    @Test
    void memberGrantAloneNeverMakesEvaluationReadyWhenT3nDeniesProposal() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "DENIED", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.delegationMemberState()).isEqualTo("ACTIVE");
        assertThat(result.delegationEffectiveState()).isEqualTo("DENIED");
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.message()).contains("effective T3N access is denied");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void unknownProposalVerdictFailsClosed() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "UNKNOWN", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.delegationEffectiveState()).isEqualTo("UNKNOWN");
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.message()).contains("could not be confirmed");
    }

    @Test
    void executorDenialKeepsEvaluationReadyButBlocksProtectedRemediation() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "DENIED", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("DENIED");
        assertThat(result.message()).contains("Policy evaluation is ready").contains("denied for the Protected Executor");
    }

    @Test
    void executorUnavailableKeepsOnlyEvaluationReady() {
        when(gateway.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, false, false, null, "testnet")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.empty());

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.executorAuthenticated()).isFalse();
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("UNKNOWN");
    }

    @Test
    void registrationMismatchDoesNotReclassifyEffectiveAuthorization() {
        when(gateway.agentRegistration()).thenReturn(Optional.of(registration("did:t3n:other", "REGISTERED")));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.agentRegistrationState()).isEqualTo("MISMATCH");
        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.message()).contains("onboarding is not confirmed");
    }

    @Test
    void scheduledProposalMemberGrantNeverTriggersReadyStateOrCheckedRestrictions() {
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "SCHEDULED", "DENIED", List.of("evaluate-action"), List.of("incident_id"), List.of(), List.of(), List.of()
        )));
        when(gateway.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.delegationMemberState()).isEqualTo("SCHEDULED");
        assertThat(result.delegationEffectiveState()).isEqualTo("DENIED");
        assertThat(result.delegationCheckedFunctions()).isEmpty();
        assertThat(result.delegationCheckedScopes()).isEmpty();
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.message()).contains("authorization window has not begun");
    }

    @Test
    void malformedDelegationStatusNormalizesToUnknownAndEmptyLists() {
        DelegationStatus malformed = new DelegationStatus("BOGUS", "INCOMPLETE", null, null, null, null, null);
        assertThat(malformed.memberState()).isEqualTo("UNKNOWN");
        assertThat(malformed.effectiveState()).isEqualTo("UNKNOWN");
        assertThat(malformed.functions()).isEmpty();
        assertThat(malformed.checkedFunctions()).isEmpty();
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

    private static EnterpriseIntegrationReadiness integration(String state) {
        boolean ready = "READY".equals(state);
        return new EnterpriseIntegrationReadiness(
            state,
            true,
            true,
            true,
            "security.example",
            "verification.example",
            ready,
            ready,
            ready,
            ready,
            List.of("revoke-credential"),
            List.of("revoke-credential"),
            List.of(new EnterpriseVerificationContract("revoke-credential", "REVOKED")),
            List.of("create-incident", "isolate-account", "notify-security"),
            "2026-09-13T21:00:00Z"
        );
    }

    private static DelegationStatus delegation(
        String memberState,
        String effectiveState,
        List<String> functions,
        List<String> scopes,
        List<String> allowedHosts,
        List<String> checkedFunctions,
        List<String> checkedScopes
    ) {
        return new DelegationStatus(memberState, effectiveState, functions, scopes, allowedHosts, checkedFunctions, checkedScopes);
    }
}
