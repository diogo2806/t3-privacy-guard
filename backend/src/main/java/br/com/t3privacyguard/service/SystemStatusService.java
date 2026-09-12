package br.com.t3privacyguard.service;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ContractIdentity;
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

        String message;
        if (!gatewayReachable) {
            message = "T3N gateway is unreachable.";
        } else if (tenant.map(TenantStatus::ready).orElse(false)
            && agent.map(AgentStatus::ready).orElse(false)
            && contract.isPresent()) {
            message = "Tenant, agent and registered T3N contract are ready.";
        } else {
            message = "Gateway is online, but one or more T3N capabilities are not ready.";
        }

        return new SystemStatusResponse(
            gatewayReachable,
            tenant.map(TenantStatus::ready).orElse(false),
            tenant.map(TenantStatus::network).orElse(null),
            tenant.map(TenantStatus::tenantDid).orElse(null),
            agent.map(AgentStatus::configured).orElse(false),
            agent.map(AgentStatus::ready).orElse(false),
            agent.map(AgentStatus::agentDid).orElse(null),
            contract.isPresent(),
            contract.map(ContractIdentity::contractId).orElse(null),
            contract.map(ContractIdentity::contractVersion).orElse(null),
            contract.map(ContractIdentity::functions).orElse(List.of()),
            message
        );
    }

    public record SystemStatusResponse(
        boolean gatewayReachable,
        boolean t3nReady,
        String network,
        String tenantDid,
        boolean agentConfigured,
        boolean agentReady,
        String agentDid,
        boolean contractRegistered,
        String contractId,
        String contractVersion,
        List<String> contractFunctions,
        String message
    ) {}
}
