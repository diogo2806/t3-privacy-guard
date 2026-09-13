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
        String delegationMemberState = proposalDelegation.map(DelegationStatus::memberState).orElse("UNKNOWN");
        String delegationEffectiveState = proposalDelegation.map(DelegationStatus::effectiveState).orElse("UNKNOWN");
        String executorDelegationMemberState = executorDelegation.map(DelegationStatus::memberState).orElse("UNKNOWN");
        String executorDelegationEffectiveState = executorDelegation.map(DelegationStatus::effectiveState).orElse("UNKNOWN");
        boolean controlsReady = tenantAuthenticated
            && agentAuthenticated
            && executorAuthenticated
            && contractResolved
            && "ACTIVE".equals(delegationEffectiveState)
            && "ACTIVE".equals(executorDelegationEffectiveState);

        String message;
        if (!gatewayReachable) {
            message = "T3N gateway is unreachable.";
        } else if ("SCHEDULED".equals(delegationMemberState) && "SCHEDULED".equals(executorDelegationMemberState)) {
            message = "Proposal and Executor Member grants exist, but their authorization windows have not begun. Effective access is not active.";
        } else if ("SCHEDULED".equals(delegationMemberState)) {
            message = "Proposal Member grant exists, but its authorization window has not begun. Effective access is not active.";
        } else if ("SCHEDULED".equals(executorDelegationMemberState)) {
            message = "Executor Member grant exists, but its authorization window has not begun. Effective access is not active.";
        } else if ("ACTIVE".equals(delegationMemberState) && "INCOMPLETE".equals(delegationEffectiveState)) {
            message = "Proposal Member grant is active, but T3N checkDelegation did not authorize effective access.";
        } else if ("ACTIVE".equals(executorDelegationMemberState) && "INCOMPLETE".equals(executorDelegationEffectiveState)) {
            message = "Executor Member grant is active, but T3N checkDelegation did not authorize effective access.";
        } else if ("ACTIVE".equals(delegationMemberState) && "UNKNOWN".equals(delegationEffectiveState)) {
            message = "Proposal Member grant is active, but the T3N effective delegation verdict is unavailable. Protected operations remain not ready.";
        } else if ("ACTIVE".equals(executorDelegationMemberState) && "UNKNOWN".equals(executorDelegationEffectiveState)) {
            message = "Executor Member grant is active, but the T3N effective delegation verdict is unavailable. Protected operations remain not ready.";
        } else if (controlsReady && "REGISTERED".equals(registrationState)) {
            message = "T3N controls are ready: tenant, proposal agent and protected executor are authenticated, T3N confirmed their effective least-privilege access, and the public Agent Card is registered.";
        } else if (controlsReady) {
            message = "T3N controls are ready with T3N-confirmed effective access, but public Agent onboarding is not confirmed as REGISTERED.";
        } else {
            message = "Gateway is online, but one or more T3N identity, contract, Member grant, or effective delegation controls are not confirmed as ready.";
        }

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
            registration.map(AgentRegistrationStatus::services).map(SystemStatusService::safeList).orElse(List.of()),
            registration.map(AgentRegistrationStatus::a2aConfigured).orElse(false),
            registration.map(AgentRegistrationStatus::a2aPublicUrl).orElse(null),
            registration.map(AgentRegistrationStatus::a2aConfigurationCheckedAt).orElse(null),
            contractResolved,
            contract.map(ContractIdentity::contractId).orElse(null),
            contract.map(ContractIdentity::contractVersion).orElse(null),
            delegationMemberState,
            delegationEffectiveState,
            proposalDelegation.map(DelegationStatus::functions).map(SystemStatusService::safeList).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::scopes).map(SystemStatusService::safeList).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::allowedHosts).map(SystemStatusService::safeList).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::satisfied).map(SystemStatusService::safeList).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::missing).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegationMemberState,
            executorDelegationEffectiveState,
            executorDelegation.map(DelegationStatus::functions).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegation.map(DelegationStatus::scopes).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegation.map(DelegationStatus::allowedHosts).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegation.map(DelegationStatus::satisfied).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegation.map(DelegationStatus::missing).map(SystemStatusService::safeList).orElse(List.of()),
            message
        );
    }

    private static String registrationState(Optional<AgentRegistrationStatus> registration, String authenticatedAgentDid) {
        if (registration.isEmpty()) return "UNAVAILABLE";
        AgentRegistrationStatus value = registration.get();
        if (authenticatedAgentDid == null || value.agentDid() == null || !authenticatedAgentDid.equals(value.agentDid())) return "MISMATCH";
        return REGISTRATION_STATES.contains(value.state()) ? value.state() : "UNAVAILABLE";
    }

    private static List<String> safeList(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
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
        boolean a2aConfigured,
        String a2aPublicUrl,
        String a2aConfigurationCheckedAt,
        boolean contractResolved,
        String contractId,
        String contractVersion,
        String delegationMemberState,
        String delegationEffectiveState,
        List<String> delegatedFunctions,
        List<String> delegatedScopes,
        List<String> allowedHosts,
        List<String> delegationSatisfied,
        List<String> delegationMissing,
        String executorDelegationMemberState,
        String executorDelegationEffectiveState,
        List<String> executorDelegatedFunctions,
        List<String> executorDelegatedScopes,
        List<String> executorAllowedHosts,
        List<String> executorDelegationSatisfied,
        List<String> executorDelegationMissing,
        String message
    ) {}
}
