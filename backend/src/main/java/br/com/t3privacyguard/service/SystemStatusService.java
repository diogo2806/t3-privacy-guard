package br.com.t3privacyguard.service;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentRegistrationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ContractIdentity;
import br.com.t3privacyguard.integration.GatewaySystemClient.DelegationStatus;
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
        Optional<AgentRegistrationStatus> registration = agent.filter(AgentStatus::ready).flatMap(ignored -> gateway.agentRegistration());
        Optional<ContractIdentity> contract = gateway.contractIdentity();
        Optional<DelegationStatus> delegation = contract.flatMap(value -> gateway.delegationStatus(value.contractId()));

        boolean tenantAuthenticated = tenant.map(TenantStatus::ready).orElse(false);
        boolean agentAuthenticated = agent.map(AgentStatus::ready).orElse(false);
        String authenticatedAgentDid = agent.map(AgentStatus::agentDid).orElse(null);
        String registrationState = registrationState(registration, authenticatedAgentDid);
        boolean contractResolved = contract.isPresent();
        String memberDelegationState = delegation.map(DelegationStatus::memberState).orElse("UNKNOWN");
        String effectiveDelegationState = delegation.map(DelegationStatus::state).orElse("UNKNOWN");
        boolean controlsReady = tenantAuthenticated && agentAuthenticated && contractResolved && "ACTIVE".equals(effectiveDelegationState);

        String message;
        if (!gatewayReachable) {
            message = "T3N gateway is unreachable.";
        } else if ("SCHEDULED".equals(memberDelegationState)) {
            message = "Member delegation exists, but its authorization window has not begun.";
        } else if ("INCOMPLETE".equals(effectiveDelegationState)) {
            message = "Member delegation was observed, but T3N did not confirm effective delegated access for the authenticated Agent.";
        } else if ("UNKNOWN".equals(effectiveDelegationState) && "ACTIVE".equals(memberDelegationState)) {
            message = "Member delegation is active, but effective delegated access could not be verified with T3N.";
        } else if (controlsReady && "REGISTERED".equals(registrationState)) {
            message = "T3N controls are ready, effective delegated access is confirmed, and the public Agent Card is registered for the authenticated Agent DID.";
        } else if (controlsReady) {
            message = "T3N controls and effective delegated access are ready, but public Agent onboarding is not confirmed as REGISTERED.";
        } else {
            message = "Gateway is online, but one or more T3N identity, contract, or delegation controls are not confirmed as ready.";
        }

        return new SystemStatusResponse(
            gatewayReachable,
            tenantAuthenticated,
            tenant.map(TenantStatus::network).orElse(null),
            tenant.map(TenantStatus::tenantDid).orElse(null),
            agent.map(AgentStatus::configured).orElse(false),
            agentAuthenticated,
            authenticatedAgentDid,
            registrationState,
            registration.map(AgentRegistrationStatus::cardUri).orElse(null),
            registration.map(AgentRegistrationStatus::cardSha256).orElse(null),
            registration.map(AgentRegistrationStatus::verifiedAt).orElse(null),
            registration.map(AgentRegistrationStatus::services).orElse(List.of()),
            contractResolved,
            contract.map(ContractIdentity::contractId).orElse(null),
            contract.map(ContractIdentity::contractVersion).orElse(null),
            memberDelegationState,
            effectiveDelegationState,
            delegation.map(DelegationStatus::functions).orElse(List.of()),
            delegation.map(DelegationStatus::scopes).orElse(List.of()),
            delegation.map(DelegationStatus::allowedHosts).orElse(List.of()),
            delegation.map(DelegationStatus::satisfied).orElse(List.of()),
            delegation.map(DelegationStatus::missing).orElse(List.of()),
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
        String agentRegistrationState,
        String agentCardUri,
        String agentCardSha256,
        String agentCardVerifiedAt,
        List<String> agentCardServices,
        boolean contractResolved,
        String contractId,
        String contractVersion,
        String memberDelegationState,
        String delegationState,
        List<String> delegatedFunctions,
        List<String> delegatedScopes,
        List<String> allowedHosts,
        List<String> delegationSatisfied,
        List<String> delegationMissing,
        String message
    ) {}
}
