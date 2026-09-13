package br.com.t3privacyguard.service;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentRegistrationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ContractIdentity;
import br.com.t3privacyguard.integration.GatewaySystemClient.DelegationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ExecutorStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.TenantStatus;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class SystemStatusService {
    private static final List<String> REGISTRATION_STATES = List.of("REGISTERED", "NOT_REGISTERED", "MISMATCH", "UNAVAILABLE");
    private final GatewaySystemClient gateway;

    public SystemStatusService(GatewaySystemClient gateway) {
        this.gateway = gateway;
    }

    public SystemStatusResponse status() {
        boolean gatewayReachable = gateway.health();
        Optional<TenantStatus> tenant = gateway.tenantStatus();
        Optional<AgentStatus> agent = gateway.agentStatus();
        Optional<ExecutorStatus> executor = gateway.executorStatus();
        Optional<AgentRegistrationStatus> registration = agent.filter(AgentStatus::ready).flatMap(ignored -> gateway.agentRegistration());
        Optional<ContractIdentity> contract = gateway.contractIdentity();
        Optional<DelegationStatus> proposalDelegation = contract.flatMap(value -> gateway.delegationStatus(value.contractId()));
        Optional<DelegationStatus> executorDelegation = contract.flatMap(value -> gateway.executorDelegationStatus(value.contractId()));

        boolean tenantAuthenticated = tenant.map(TenantStatus::ready).orElse(false);
        boolean agentAuthenticated = agent.map(AgentStatus::ready).orElse(false);
        boolean executorAuthenticated = executor.map(ExecutorStatus::ready).orElse(false);
        String authenticatedAgentDid = agent.map(AgentStatus::agentDid).orElse(null);
        String authenticatedExecutorDid = executor.map(ExecutorStatus::executorDid).orElse(null);
        String registrationState = registrationState(registration, authenticatedAgentDid);
        boolean contractResolved = contract.isPresent();

        String proposalMemberState = proposalDelegation.map(DelegationStatus::memberState).orElse("UNKNOWN");
        String proposalEffectiveState = proposalDelegation.map(DelegationStatus::effectiveState).orElse("UNKNOWN");
        String executorMemberState = executorDelegation.map(DelegationStatus::memberState).orElse("UNKNOWN");
        String executorEffectiveState = executorDelegation.map(DelegationStatus::effectiveState).orElse("UNKNOWN");

        boolean evaluationReady = tenantAuthenticated
            && agentAuthenticated
            && contractResolved
            && "ACTIVE".equals(proposalEffectiveState);
        boolean protectedRemediationReady = evaluationReady
            && executorAuthenticated
            && "ACTIVE".equals(executorEffectiveState);

        String message = statusMessage(
            gatewayReachable,
            registrationState,
            proposalMemberState,
            proposalEffectiveState,
            executorMemberState,
            executorEffectiveState,
            evaluationReady,
            protectedRemediationReady
        );

        return new SystemStatusResponse(
            gatewayReachable,
            tenantAuthenticated,
            tenant.map(TenantStatus::network).orElse(null),
            tenant.map(TenantStatus::tenantDid).orElse(null),
            agent.map(AgentStatus::configured).orElse(false),
            agentAuthenticated,
            authenticatedAgentDid,
            executor.map(ExecutorStatus::configured).orElse(false),
            executorAuthenticated,
            authenticatedExecutorDid,
            registrationState,
            registration.map(AgentRegistrationStatus::cardUri).orElse(null),
            registration.map(AgentRegistrationStatus::cardSha256).orElse(null),
            registration.map(AgentRegistrationStatus::verifiedAt).orElse(null),
            registration.map(AgentRegistrationStatus::services).orElse(List.of()),
            contractResolved,
            contract.map(ContractIdentity::contractId).orElse(null),
            contract.map(ContractIdentity::contractVersion).orElse(null),
            evaluationReady,
            protectedRemediationReady,
            proposalMemberState,
            proposalEffectiveState,
            proposalDelegation.map(DelegationStatus::functions).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::scopes).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::allowedHosts).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::checkedFunctions).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::checkedScopes).orElse(List.of()),
            executorMemberState,
            executorEffectiveState,
            executorDelegation.map(DelegationStatus::functions).orElse(List.of()),
            executorDelegation.map(DelegationStatus::scopes).orElse(List.of()),
            executorDelegation.map(DelegationStatus::allowedHosts).orElse(List.of()),
            executorDelegation.map(DelegationStatus::checkedFunctions).orElse(List.of()),
            executorDelegation.map(DelegationStatus::checkedScopes).orElse(List.of()),
            message
        );
    }

    private static String statusMessage(
        boolean gatewayReachable,
        String registrationState,
        String proposalMemberState,
        String proposalEffectiveState,
        String executorMemberState,
        String executorEffectiveState,
        boolean evaluationReady,
        boolean protectedRemediationReady
    ) {
        if (!gatewayReachable) return "T3N gateway is unreachable.";
        if ("SCHEDULED".equals(proposalMemberState) && "SCHEDULED".equals(executorMemberState)) {
            return "Proposal and Executor Member grants exist, but their authorization windows have not begun. Effective T3N access is not confirmed.";
        }
        if ("SCHEDULED".equals(proposalMemberState)) {
            return "Proposal Member grant exists, but its authorization window has not begun. Effective T3N access is not confirmed.";
        }
        if ("SCHEDULED".equals(executorMemberState)) {
            return "Executor Member grant exists, but its authorization window has not begun. Protected remediation is not ready.";
        }
        if (!"ACTIVE".equals(proposalEffectiveState)) {
            return effectiveFailure("Proposal", proposalMemberState, proposalEffectiveState, "evaluate-action");
        }
        if (!"ACTIVE".equals(executorEffectiveState)) {
            return "Proposal evaluation has confirmed effective T3N access. "
                + effectiveFailure("Protected Executor", executorMemberState, executorEffectiveState, "execute-remediation / verify-remediation");
        }
        if (protectedRemediationReady && "REGISTERED".equals(registrationState)) {
            return "T3N controls are ready: effective access is confirmed independently for Proposal evaluation and Protected Executor remediation, and the public Agent Card is registered.";
        }
        if (protectedRemediationReady) {
            return "Effective T3N access is confirmed for Proposal evaluation and Protected Executor remediation, but public Agent onboarding is not confirmed as REGISTERED.";
        }
        if (evaluationReady) {
            return "Proposal evaluation has confirmed effective T3N access, but protected remediation is not ready.";
        }
        return "Gateway is online, but one or more T3N identity, contract, Member grant, or effective authorization controls are not confirmed.";
    }

    private static String effectiveFailure(String principal, String memberState, String effectiveState, String functions) {
        if ("ACTIVE".equals(memberState) && "DENIED".equals(effectiveState)) {
            return principal + " Member grant is active, but effective T3N access is denied for " + functions + ".";
        }
        if ("ACTIVE".equals(memberState)) {
            return principal + " Member grant is active, but effective T3N access is unknown for " + functions + ".";
        }
        return principal + " Member grant is " + memberState + "; effective T3N access is not confirmed for " + functions + ".";
    }

    private static String registrationState(Optional<AgentRegistrationStatus> registration, String authenticatedAgentDid) {
        if (registration.isEmpty()) return "UNAVAILABLE";
        AgentRegistrationStatus value = registration.get();
        if (authenticatedAgentDid == null || value.agentDid() == null || !authenticatedAgentDid.equals(value.agentDid())) return "MISMATCH";
        return REGISTRATION_STATES.contains(value.state()) ? value.state() : "UNAVAILABLE";
    }

    public record SystemStatusResponse(
        boolean gatewayReachable,
        boolean tenantAuthenticated,
        String network,
        String tenantDid,
        boolean agentConfigured,
        boolean agentAuthenticated,
        String agentDid,
        boolean executorConfigured,
        boolean executorAuthenticated,
        String executorDid,
        String agentRegistrationState,
        String agentCardUri,
        String agentCardSha256,
        String agentCardVerifiedAt,
        List<String> agentCardServices,
        boolean contractResolved,
        String contractId,
        String contractVersion,
        boolean evaluationReady,
        boolean protectedRemediationReady,
        String proposalMemberState,
        String proposalEffectiveState,
        List<String> proposalDelegatedFunctions,
        List<String> proposalDelegatedScopes,
        List<String> proposalAllowedHosts,
        List<String> proposalCheckedFunctions,
        List<String> proposalCheckedScopes,
        String executorMemberState,
        String executorEffectiveState,
        List<String> executorDelegatedFunctions,
        List<String> executorDelegatedScopes,
        List<String> executorAllowedHosts,
        List<String> executorCheckedFunctions,
        List<String> executorCheckedScopes,
        String message
    ) {}
}
