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
    private static final String CONTRACT_ID = "z:tenant:privacy-guard";
    private static final List<String> SCOPES = List.of("incident_id", "credential_id", "reason");

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
        when(gateway.contractIdentity()).thenReturn(Optional.of(new ContractIdentity(CONTRACT_ID, "0.4.0")));
    }

    private static DelegationStatus proposal(String memberState, String effectiveState) {
        return new DelegationStatus(
            memberState,
            effectiveState,
            List.of("evaluate-action"),
            SCOPES,
            List.of(),
            "ACTIVE".equals(memberState) ? List.of("evaluate-action") : List.of(),
            "ACTIVE".equals(memberState) ? SCOPES : List.of()
        );
    }

    private static DelegationStatus executor(String memberState, String effectiveState) {
        return new DelegationStatus(
            memberState,
            effectiveState,
            List.of("execute-remediation", "verify-remediation"),
            SCOPES,
            List.of("security.example", "verification.example"),
            "ACTIVE".equals(memberState) ? List.of("execute-remediation", "verify-remediation") : List.of(),
            "ACTIVE".equals(memberState) ? SCOPES : List.of()
        );
    }

    @Test
    void reportsMemberGrantAndEffectiveAccessSeparately() {
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(proposal("ACTIVE", "ACTIVE")));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.tenantAuthenticated()).isTrue();
        assertThat(result.agentAuthenticated()).isTrue();
        assertThat(result.agentDid()).isEqualTo("did:t3n:proposal-agent");
        assertThat(result.executorAuthenticated()).isTrue();
        assertThat(result.executorDid()).isEqualTo("did:t3n:protected-executor");
        assertThat(result.proposalMemberState()).isEqualTo("ACTIVE");
        assertThat(result.proposalEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.proposalDelegatedFunctions()).containsExactly("evaluate-action");
        assertThat(result.proposalCheckedFunctions()).containsExactly("evaluate-action");
        assertThat(result.executorMemberState()).isEqualTo("ACTIVE");
        assertThat(result.executorEffectiveState()).isEqualTo("ACTIVE");
        assertThat(result.executorCheckedFunctions()).containsExactly("execute-remediation", "verify-remediation");
        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.message()).contains("effective access is confirmed");
    }

    @Test
    void activeMemberGrantWithDeniedProposalCheckFailsClosed() {
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(proposal("ACTIVE", "DENIED")));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.proposalMemberState()).isEqualTo("ACTIVE");
        assertThat(result.proposalEffectiveState()).isEqualTo("DENIED");
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.message()).contains("effective T3N access is denied").doesNotContain("T3N controls are ready");
    }

    @Test
    void unknownProposalEffectiveAccessNeverBecomesReady() {
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(proposal("ACTIVE", "UNKNOWN")));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.message()).contains("effective T3N access is unknown").doesNotContain("T3N controls are ready");
    }

    @Test
    void deniedExecutorKeepsEvaluationReadyButProtectedRemediationClosed() {
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(proposal("ACTIVE", "ACTIVE")));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(executor("ACTIVE", "DENIED")));

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.executorEffectiveState()).isEqualTo("DENIED");
        assertThat(result.message()).contains("Proposal evaluation has confirmed effective T3N access")
            .contains("Protected Executor Member grant is active")
            .contains("effective T3N access is denied")
            .doesNotContain("T3N controls are ready");
    }

    @Test
    void executorUnavailableFailsProtectedReadinessEvenWhenProposalIsEffectivelyAuthorized() {
        when(gateway.executorStatus()).thenReturn(Optional.of(new ExecutorStatus(true, false, false, null, "testnet")));
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(proposal("ACTIVE", "ACTIVE")));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.empty());

        var result = service.status();

        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isFalse();
        assertThat(result.executorEffectiveState()).isEqualTo("UNKNOWN");
        assertThat(result.message()).doesNotContain("T3N controls are ready");
    }

    @Test
    void registrationDidMismatchDoesNotChangeConfirmedTechnicalAuthorization() {
        when(gateway.agentRegistration()).thenReturn(Optional.of(new AgentRegistrationStatus("did:t3n:other", "REGISTERED", "https://node.example/card", "a".repeat(64), "2026-09-12T20:00:00Z", List.of("DID"))));
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(proposal("ACTIVE", "ACTIVE")));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.agentRegistrationState()).isEqualTo("MISMATCH");
        assertThat(result.evaluationReady()).isTrue();
        assertThat(result.protectedRemediationReady()).isTrue();
        assertThat(result.message()).contains("Effective T3N access is confirmed").contains("onboarding is not confirmed");
    }

    @Test
    void scheduledMemberGrantNeverBecomesEffectivelyReady() {
        when(gateway.delegationStatus(CONTRACT_ID)).thenReturn(Optional.of(proposal("SCHEDULED", "DENIED")));
        when(gateway.executorDelegationStatus(CONTRACT_ID)).thenReturn(Optional.of(executor("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.proposalMemberState()).isEqualTo("SCHEDULED");
        assertThat(result.proposalEffectiveState()).isEqualTo("DENIED");
        assertThat(result.evaluationReady()).isFalse();
        assertThat(result.message()).contains("authorization window has not begun").contains("Effective T3N access is not confirmed");
    }

    @Test
    void missingOrInvalidDelegationFieldsNormalizeToUnknownAndEmptyLists() {
        DelegationStatus malformed = new DelegationStatus(null, "unexpected", null, null, null, null, null);

        assertThat(malformed.memberState()).isEqualTo("UNKNOWN");
        assertThat(malformed.effectiveState()).isEqualTo("UNKNOWN");
        assertThat(malformed.functions()).isEmpty();
        assertThat(malformed.scopes()).isEmpty();
        assertThat(malformed.allowedHosts()).isEmpty();
        assertThat(malformed.checkedFunctions()).isEmpty();
        assertThat(malformed.checkedScopes()).isEmpty();
    }
}
