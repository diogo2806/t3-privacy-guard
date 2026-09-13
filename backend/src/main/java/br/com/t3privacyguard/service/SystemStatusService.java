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
        String delegationState = proposalDelegation.map(DelegationStatus::state).orElse("UNKNOWN");
        String executorDelegationState = executorDelegation.map(DelegationStatus::state).orElse("UNKNOWN");
        boolean controlsReady = tenantAuthenticated
            && agentAuthenticated
            && executorAuthenticated
            && contractResolved
            && "ACTIVE".equals(delegationState)
            && "ACTIVE".equals(executorDelegationState);

        String message;
        if (!gatewayReachable) {
            message = "T3N gateway is unreachable.";
        } else if (controlsReady && "REGISTERED".equals(registrationState)) {
            message = "T3N controls are ready: tenant, proposal agent and protected executor are authenticated with active least-privilege delegations, and the public Agent Card is registered.";
        } else if (controlsReady) {
            message = "T3N controls are ready, but public Agent onboarding is not confirmed as REGISTERED.";
        } else {
            message = "Gateway is online, but one or more T3N identity, contract, proposal delegation, or protected executor controls are not confirmed as ready.";
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
            registration.map(AgentRegistrationStatus::services).orElse(List.of()),
            contractResolved,
            contract.map(ContractIdentity::contractId).orElse(null),
            contract.map(ContractIdentity::contractVersion).orElse(null),
            delegationState,
            proposalDelegation.map(DelegationStatus::functions).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::allowedHosts).orElse(List.of()),
            executorDelegationState,
            executorDelegation.map(DelegationStatus::functions).orElse(List.of()),
            executorDelegation.map(DelegationStatus::allowedHosts).orElse(List.of()),
            message
        );
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
        String delegationState,
        List<String> delegatedFunctions,
        List<String> allowedHosts,
        String executorDelegationState,
        List<String> executorDelegatedFunctions,
        List<String> executorAllowedHosts,
        String message
    ) {}
}
