package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentRegistrationStatus;
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

    private static DelegationStatus delegation(String effective, String member) {
        return new DelegationStatus(
            effective,
            member,
            List.of("evaluate-action", "execute-remediation"),
            List.of("incident_id"),
            List.of("postman-echo.com"),
            List.of("member_delegation"),
            List.of()
        );
    }

    private void readyBase(String registrationState) {
        when(gateway.health()).thenReturn(true);
        when(gateway.tenantStatus()).thenReturn(Optional.of(new TenantStatus(true, true, "did:t3n:tenant", "testnet")));
        when(gateway.agentStatus()).thenReturn(Optional.of(new AgentStatus(true, true, true, "did:t3n:agent", "testnet")));
        when(gateway.agentRegistration()).thenReturn(Optional.of(new AgentRegistrationStatus(
            "did:t3n:agent", registrationState, "https://node.example/card", "a".repeat(64), "2026-09-12T20:00:00Z", List.of("DID")
        )));
        when(gateway.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("z:tenant:privacy-guard", "0.3.0")));
    }

    @Test
    void reportsMemberAndEffectiveDelegationSeparately() {
        readyBase("REGISTERED");
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.tenantAuthenticated()).isTrue();
        assertThat(result.agentAuthenticated()).isTrue();
        assertThat(result.memberDelegationState()).isEqualTo("ACTIVE");
        assertThat(result.delegationState()).isEqualTo("ACTIVE");
        assertThat(result.delegatedFunctions()).containsExactly("evaluate-action", "execute-remediation");
        assertThat(result.delegatedScopes()).containsExactly("incident_id");
        assertThat(result.delegationSatisfied()).containsExactly("member_delegation");
        assertThat(result.message()).contains("effective delegated access is confirmed");
    }

    @Test
    void memberActiveDoesNotBecomeReadyWhenPlatformDoesNotAuthorize() {
        readyBase("REGISTERED");
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation("INCOMPLETE", "ACTIVE")));

        var result = service.status();

        assertThat(result.memberDelegationState()).isEqualTo("ACTIVE");
        assertThat(result.delegationState()).isEqualTo("INCOMPLETE");
        assertThat(result.message()).contains("did not confirm effective delegated access");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void memberActiveDoesNotBecomeReadyWhenEffectiveCheckIsUnknown() {
        readyBase("REGISTERED");
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation("UNKNOWN", "ACTIVE")));

        var result = service.status();

        assertThat(result.memberDelegationState()).isEqualTo("ACTIVE");
        assertThat(result.delegationState()).isEqualTo("UNKNOWN");
        assertThat(result.message()).contains("could not be verified with T3N");
        assertThat(result.message()).doesNotContain("controls are ready");
    }

    @Test
    void registrationDidMismatchDoesNotReclassifyEffectiveAuthorization() {
        readyBase("REGISTERED");
        when(gateway.agentRegistration()).thenReturn(Optional.of(new AgentRegistrationStatus(
            "did:t3n:other", "REGISTERED", "https://node.example/card", "a".repeat(64), "2026-09-12T20:00:00Z", List.of("DID")
        )));
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation("ACTIVE", "ACTIVE")));

        var result = service.status();

        assertThat(result.agentRegistrationState()).isEqualTo("MISMATCH");
        assertThat(result.delegationState()).isEqualTo("ACTIVE");
        assertThat(result.message()).contains("controls and effective delegated access are ready").contains("onboarding is not confirmed");
    }

    @Test
    void missingDelegationStatusFailsClosed() {
        readyBase("REGISTERED");
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.empty());

        var result = service.status();

        assertThat(result.memberDelegationState()).isEqualTo("UNKNOWN");
        assertThat(result.delegationState()).isEqualTo("UNKNOWN");
        assertThat(result.message()).contains("not confirmed as ready");
    }

    @Test
    void scheduledMemberDelegationNeverBecomesReady() {
        readyBase("REGISTERED");
        when(gateway.delegationStatus("z:tenant:privacy-guard")).thenReturn(Optional.of(delegation("INCOMPLETE", "SCHEDULED")));

        var result = service.status();

        assertThat(result.memberDelegationState()).isEqualTo("SCHEDULED");
        assertThat(result.delegationState()).isEqualTo("INCOMPLETE");
        assertThat(result.message()).isEqualTo("Member delegation exists, but its authorization window has not begun.");
        assertThat(result.message()).doesNotContain("controls are ready");
    }
}
