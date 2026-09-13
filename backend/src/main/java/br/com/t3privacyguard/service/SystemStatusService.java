package br.com.t3privacyguard.service;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ContractIdentity;
import br.com.t3privacyguard.integration.GatewaySystemClient.DelegationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.TenantStatus;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class SystemStatusService {
    private final GatewaySystemClient gateway;

    public SystemStatusService(GatewaySystemClient gateway) {
        this.gateway = gateway;
    }

    public SystemStatusResponse status() {
        boolean gatewayReachable = gateway.health();
        Optional<TenantStatus> tenant = gateway.tenantStatus();
        Optional<AgentStatus> agent = gateway.agentStatus();
        Optional<ContractIdentity> contract = gateway.contractIdentity();
        Optional<DelegationStatus> delegation = contract.flatMap(value -> gateway.delegationStatus(value.contractId()));

        boolean tenantAuthenticated = tenant.map(TenantStatus::ready).orElse(false);
        boolean agentAuthenticated = agent.map(AgentStatus::ready).orElse(false);
        boolean contractResolved = contract.isPresent();
        String delegationState = delegation.map(DelegationStatus::state).orElse("UNKNOWN");
        String registrationState = agent.map(AgentStatus::agentRegistrationState).filter(value -> value != null && !value.isBlank()).orElse("UNAVAILABLE");
        boolean operational = tenantAuthenticated && agentAuthenticated && contractResolved && "ACTIVE".equals(delegationState);

        String message;
        if (!gatewayReachable) {
            message = "T3N gateway is unreachable.";
        } else if (operational && "REGISTERED".equals(registrationState)) {
            message = "Tenant and agent are authenticated, public agent onboarding is registered, the contract is resolved, and delegation is active.";
        } else if (operational) {
            message = "Authorization controls are operational, but public Agent Card onboarding is not confirmed as registered.";
        } else {
            message = "Gateway is online, but one or more T3N operational states are not confirmed as ready.";
        }

        return new SystemStatusResponse(
            gatewayReachable,
            tenantAuthenticated,
            tenant.map(TenantStatus::network).orElse(null),
            tenant.map(TenantStatus::tenantDid).orElse(null),
            agent.map(AgentStatus::configured).orElse(false),
            agentAuthenticated,
            agent.map(AgentStatus::agentDid).orElse(null),
            registrationState,
            agent.map(AgentStatus::agentCardUri).orElse(null),
            agent.map(AgentStatus::agentCardSha256).orElse(null),
            agent.map(AgentStatus::agentCardVerifiedAt).orElse(null),
            agent.map(AgentStatus::agentCardServices).orElse(List.of()),
            contractResolved,
            contract.map(ContractIdentity::contractId).orElse(null),
            contract.map(ContractIdentity::contractVersion).orElse(null),
            delegationState,
            delegation.map(DelegationStatus::functions).orElse(List.of()),
            delegation.map(DelegationStatus::allowedHosts).orElse(List.of()),
            message
        );
    }

    public record SystemStatusResponse(
        boolean gatewayReachable,
        boolean tenantAuthenticated,
        String network,
        String tenantDid,
        boolean agentConfigured,
        boolean agentAuthenticated,
        String agentDid,
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
        String message
    ) {}
}
