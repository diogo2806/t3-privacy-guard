package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.integration.RuntimeStatusClient;
import br.com.t3privacyguard.integration.RuntimeStatusClient.AgentStatus;
import br.com.t3privacyguard.integration.RuntimeStatusClient.ContractIdentity;
import br.com.t3privacyguard.integration.RuntimeStatusClient.DelegationStatus;
import br.com.t3privacyguard.integration.RuntimeStatusClient.EnterpriseIntegrationReadiness;
import br.com.t3privacyguard.integration.RuntimeStatusClient.EnterpriseVerificationContract;
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
class SystemStatusServiceTest {
    @Mock RuntimeStatusClient runtime;
    @Mock SecurityRemediationCredential remediationCredential;
    @InjectMocks SystemStatusService service;

    @BeforeEach
    void baseStatus() {
        when(runtime.health()).thenReturn(true);
        when(runtime.tenantStatus()).thenReturn(Optional.of(new TenantStatus(true, true, "agent:tenant", "selfhosted")));
        when(runtime.agentStatus()).thenReturn(Optional.of(new AgentStatus(true, true, true, "agent:proposal-agent", "selfhosted")));
        when(runtime.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, true, true, "agent:protected-executor", "selfhosted")));
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.of(integration("READY")));
        when(runtime.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("z:tenant:privacy-guard", "0.4.0")));
        when(remediationCredential.isConfigured()).thenReturn(true);
    }

    @Test
    void reportsIndependentEffectiveReadiness() {
        when(runtime.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(runtime.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id"), List.of("security.example", "verification.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.enterpriseIntegrationState()).isEqualTo("READY");
        assertThat(result.enterpriseIntegrationDiagnosticCode()).isEqualTo("NONE");
        assertThat(result.enterpriseIntegrationReady()).isTrue();
        assertThat(result.firstPartyRemediationAdapterConfigured()).isTrue();
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
        assertThat(result.message()).startsWith("guard-runtime controls are ready");
    }

    @Test
    void callerIdsAreEnoughForReadiness() {
        when(runtime.tenantStatus()).thenReturn(Optional.of(new TenantStatus(true, true, "acme", "selfhosted")));
        when(runtime.agentStatus()).thenReturn(Optional.of(new AgentStatus(true, true, true, "agent:proposal", "selfhosted")));
        when(runtime.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, true, true, "agent:executor", "selfhosted")));
        when(runtime.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("guard-runtime", "1.0.0")));
        when(runtime.delegationStatus("guard-runtime")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of(), List.of(), List.of("evaluate-action"), List.of()
        )));
        when(runtime.executorDelegationStatus("guard-runtime")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of(), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of()
        )));

        var result = service.status();

        assertThat(result.network()).isEqualTo("selfhosted");
        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.executorDid()).isEqualTo("agent:executor");
        assertThat(result.message()).startsWith("guard-runtime controls are ready").doesNotContain("T3N");
    }

    @Test
    void runtimeOutageUsesTheRuntimeDiagnostic() {
        when(runtime.tenantStatus()).thenReturn(Optional.of(new TenantStatus(false, false, null, "selfhosted")));
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.empty());
        when(runtime.contractIdentity()).thenReturn(Optional.empty());

        var result = service.status();

        assertThat(result.enterpriseIntegrationDiagnosticCode()).isEqualTo("TRUST_RUNTIME_UNAVAILABLE");
        assertThat(result.message()).doesNotContain("T3N");
    }

    @Test
    void enterpriseMismatchDoesNotRedefineProtectedRemediationReadiness() {
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.of(integration("MISMATCH")));
        when(runtime.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(runtime.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.enterpriseIntegrationState()).isEqualTo("MISMATCH");
        assertThat(result.enterpriseIntegrationDiagnosticCode()).isEqualTo("NONE");
        assertThat(result.enterpriseIntegrationReady()).isFalse();
    }

    @Test
    void propagatesSanitizedEnterpriseDiagnosticWithoutChangingRuntimeReadiness() {
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.of(integrationUnknown("POLICY_UNAVAILABLE")));
        when(runtime.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(runtime.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.enterpriseIntegrationState()).isEqualTo("UNKNOWN");
        assertThat(result.enterpriseIntegrationDiagnosticCode()).isEqualTo("POLICY_UNAVAILABLE");
        assertThat(result.enterpriseIntegrationReady()).isFalse();
    }

    @Test
    void unavailableEnterpriseReadinessFailsClosedWithoutChangingRuntimeReadiness() {
        when(runtime.enterpriseIntegrationReadiness()).thenReturn(Optional.empty());
        when(runtime.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(runtime.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.enterpriseIntegrationState()).isEqualTo("UNKNOWN");
        assertThat(result.enterpriseIntegrationDiagnosticCode()).isEqualTo("TRUST_RUNTIME_UNAVAILABLE");
        assertThat(result.enterpriseIntegrationReady()).isFalse();
        assertThat(result.enterpriseExecutionHost()).isNull();
        assertThat(result.enterpriseSupportedVerifiedActions()).isEmpty();
    }

    @Test
    void unauthenticatedProposalAgentBlocksEvaluation() {
        when(runtime.agentStatus()).thenReturn(Optional.of(new AgentStatus(true, false, false, null, "selfhosted")));

        var result = service.status();

        assertThat(result.agentAuthenticated()).isFalse();
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
    }

    @Test
    void knownCallerWithoutTheGrantNeverMakesEvaluationReady() {
        when(runtime.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "DENIED", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(runtime.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.delegationMemberState()).isEqualTo("ACTIVE");
        assertThat(result.delegationEffectiveState()).isEqualTo("DENIED");
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.message()).contains("not granted evaluate-action");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void unknownProposalVerdictFailsClosed() {
        when(runtime.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "UNKNOWN", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(runtime.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
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
        when(runtime.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(runtime.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "DENIED", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("DENIED");
        assertThat(result.message()).contains("Policy evaluation is ready").contains("protected executor is not granted");
    }

    @Test
    void executorUnavailableKeepsOnlyEvaluationReady() {
        when(runtime.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, false, false, null, "selfhosted")));
        when(runtime.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("evaluate-action"), List.of("incident_id"), List.of(),
            List.of("evaluate-action"), List.of("incident_id", "credential_id", "reason")
        )));
        when(runtime.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.empty());

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.executorAuthenticated()).isFalse();
        assertThat(result.executorDelegationEffectiveState()).isEqualTo("UNKNOWN");
    }

    @Test
    void scheduledProposalMemberGrantNeverTriggersReadyStateOrCheckedRestrictions() {
        when(runtime.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "SCHEDULED", "DENIED", List.of("evaluate-action"), List.of("incident_id"), List.of(), List.of(), List.of()
        )));
        when(runtime.executorDelegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation(
            "ACTIVE", "ACTIVE", List.of("execute-remediation", "verify-remediation"), List.of("incident_id"), List.of("security.example"),
            List.of("execute-remediation", "verify-remediation"), List.of("incident_id", "credential_id", "reason")
        )));

        var result = service.status();

        assertThat(result.delegationMemberState()).isEqualTo("SCHEDULED");
        assertThat(result.delegationEffectiveState()).isEqualTo("DENIED");
        assertThat(result.delegationCheckedFunctions()).isEmpty();
        assertThat(result.delegationCheckedScopes()).isEmpty();
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.message()).contains("does not recognize the proposal agent credential");
    }

    private static EnterpriseIntegrationReadiness integration(String state) {
        boolean ready = "READY".equals(state);
        return new EnterpriseIntegrationReadiness(
            state,
            "NONE",
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

    private static EnterpriseIntegrationReadiness integrationUnknown(String diagnosticCode) {
        return new EnterpriseIntegrationReadiness(
            "UNKNOWN",
            diagnosticCode,
            false,
            false,
            false,
            null,
            null,
            false,
            false,
            false,
            false,
            List.of("revoke-credential", "notify-security"),
            List.of("revoke-credential", "notify-security"),
            List.of(new EnterpriseVerificationContract("revoke-credential", "REVOKED")),
            List.of(),
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
