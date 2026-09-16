package br.com.t3privacyguard.service;

import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentRegistrationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.AgentStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.ContractIdentity;
import br.com.t3privacyguard.integration.GatewaySystemClient.DelegationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.EnterpriseIntegrationReadiness;
import br.com.t3privacyguard.integration.GatewaySystemClient.EnterpriseVerificationContract;
import br.com.t3privacyguard.integration.GatewaySystemClient.ExecutorStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient.TenantStatus;
import br.com.t3privacyguard.security.SecurityRemediationCredential;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

@Service
public class SystemStatusService {
    private static final List<String> REGISTRATION_STATES = List.of("REGISTERED", "NOT_REGISTERED", "MISMATCH", "UNAVAILABLE");
    private final GatewaySystemClient gateway;
    private final SecurityRemediationCredential remediationCredential;

    public SystemStatusService(GatewaySystemClient gateway, SecurityRemediationCredential remediationCredential) {
        this.gateway = gateway;
        this.remediationCredential = remediationCredential;
    }

    public SystemStatusResponse status() {
        boolean gatewayReachable = gateway.health();
        Optional<TenantStatus> tenant = gateway.tenantStatus();
        Optional<AgentStatus> agent = gateway.agentStatus();
        Optional<ExecutorStatus> executor = gateway.executorStatus();
        Optional<AgentRegistrationStatus> registration = gatewayReachable ? gateway.agentRegistration() : Optional.empty();
        Optional<EnterpriseIntegrationReadiness> enterpriseIntegration = gatewayReachable ? gateway.enterpriseIntegrationReadiness() : Optional.empty();
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
        String enterpriseIntegrationState = enterpriseIntegration.map(EnterpriseIntegrationReadiness::state).orElse("UNKNOWN");
        boolean enterpriseIntegrationReady = "READY".equals(enterpriseIntegrationState);

        boolean evaluationReady = tenantAuthenticated
            && agentAuthenticated
            && contractResolved
            && "ACTIVE".equals(delegationMemberState)
            && "ACTIVE".equals(delegationEffectiveState);
        boolean protectedRemediationReady = evaluationReady
            && executorAuthenticated
            && "ACTIVE".equals(executorDelegationMemberState)
            && "ACTIVE".equals(executorDelegationEffectiveState);

        String message = statusMessage(
            gatewayReachable,
            delegationMemberState,
            delegationEffectiveState,
            executorDelegationMemberState,
            executorDelegationEffectiveState,
            evaluationReady,
            protectedRemediationReady,
            registrationState
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
            registration.map(AgentRegistrationStatus::services).map(SystemStatusService::safeList).orElse(List.of()),
            registration.map(AgentRegistrationStatus::a2aConfigured).orElse(false),
            registration.map(AgentRegistrationStatus::a2aPublicUrl).orElse(null),
            registration.map(AgentRegistrationStatus::a2aConfigurationCheckedAt).orElse(null),
            contractResolved,
            contract.map(ContractIdentity::contractId).orElse(null),
            contract.map(ContractIdentity::contractVersion).orElse(null),
            evaluationReady,
            protectedRemediationReady,
            enterpriseIntegrationState,
            enterpriseIntegrationReady,
            remediationCredential.isConfigured(),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::executionConfigured).orElse(false),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::verificationConfigured).orElse(false),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::credentialConfigured).orElse(false),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::executionHost).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::verificationHost).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::policyAllowsExecutionHost).orElse(false),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::policyAllowsVerificationHost).orElse(false),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::executorDelegationAllowsExecutionHost).orElse(false),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::executorDelegationAllowsVerificationHost).orElse(false),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::supportedExecutableActions).map(SystemStatusService::safeList).orElse(List.of()),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::supportedVerifiedActions).map(SystemStatusService::safeList).orElse(List.of()),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::verificationContracts).map(SystemStatusService::safeVerificationContracts).orElse(List.of()),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::evaluationOnlyActions).map(SystemStatusService::safeList).orElse(List.of()),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::checkedAt).orElse(null),
            delegationMemberState,
            delegationEffectiveState,
            proposalDelegation.map(DelegationStatus::functions).map(SystemStatusService::safeList).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::scopes).map(SystemStatusService::safeList).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::allowedHosts).map(SystemStatusService::safeList).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::checkedFunctions).map(SystemStatusService::safeList).orElse(List.of()),
            proposalDelegation.map(DelegationStatus::checkedScopes).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegationMemberState,
            executorDelegationEffectiveState,
            executorDelegation.map(DelegationStatus::functions).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegation.map(DelegationStatus::scopes).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegation.map(DelegationStatus::allowedHosts).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegation.map(DelegationStatus::checkedFunctions).map(SystemStatusService::safeList).orElse(List.of()),
            executorDelegation.map(DelegationStatus::checkedScopes).map(SystemStatusService::safeList).orElse(List.of()),
            message
        );
    }

    private static String statusMessage(
        boolean gatewayReachable,
        String proposalMemberState,
        String proposalEffectiveState,
        String executorMemberState,
        String executorEffectiveState,
        boolean evaluationReady,
        boolean protectedRemediationReady,
        String registrationState
    ) {
        if (!gatewayReachable) return "T3N gateway is unreachable.";
        if ("SCHEDULED".equals(proposalMemberState) && "SCHEDULED".equals(executorMemberState)) {
            return "Proposal and Executor Member grants exist, but their authorization windows have not begun.";
        }
        if ("SCHEDULED".equals(proposalMemberState)) return "Proposal Member grant exists, but its authorization window has not begun.";
        if ("SCHEDULED".equals(executorMemberState) && evaluationReady) return "Policy evaluation is ready, but the Executor Member grant window has not begun; protected remediation remains unavailable.";
        if (!"ACTIVE".equals(proposalMemberState)) return "Proposal Member grant is not active; policy evaluation is not ready.";
        if ("DENIED".equals(proposalEffectiveState)) return "Proposal Member grant is active, but effective T3N access is denied for the required evaluation function/scopes.";
        if (!"ACTIVE".equals(proposalEffectiveState)) return "Proposal Member grant is active, but effective T3N access could not be confirmed for policy evaluation.";
        if (evaluationReady && !"ACTIVE".equals(executorMemberState)) return "Policy evaluation is ready, but the Executor Member grant is not active; protected remediation remains unavailable.";
        if (evaluationReady && "DENIED".equals(executorEffectiveState)) return "Policy evaluation is ready, but effective T3N access is denied for the Protected Executor.";
        if (evaluationReady && !"ACTIVE".equals(executorEffectiveState)) return "Policy evaluation is ready, but effective T3N access could not be confirmed for the Protected Executor.";
        if (protectedRemediationReady && "REGISTERED".equals(registrationState)) {
            return "T3N controls are ready: effective Proposal and Protected Executor access is confirmed for exact least-privilege functions/scopes, and the public Agent Card is registered.";
        }
        if (protectedRemediationReady) return "T3N controls are ready with effective Proposal and Protected Executor access confirmed, but public Agent onboarding is not confirmed as REGISTERED.";
        return "Gateway is online, but one or more T3N identity, contract, Member grant, or effective-access checks are not confirmed as ready.";
    }

    private static String registrationState(Optional<AgentRegistrationStatus> registration, String authenticatedAgentDid) {
        if (registration.isEmpty()) return "UNAVAILABLE";
        AgentRegistrationStatus value = registration.get();
        if (authenticatedAgentDid == null || authenticatedAgentDid.isBlank()) return "UNAVAILABLE";
        if (value.agentDid() == null || !authenticatedAgentDid.equals(value.agentDid())) return "MISMATCH";
        return REGISTRATION_STATES.contains(value.state()) ? value.state() : "UNAVAILABLE";
    }

    private static List<String> safeList(List<String> values) {
        return values == null ? List.of() : List.copyOf(values);
    }

    private static List<EnterpriseVerificationContract> safeVerificationContracts(List<EnterpriseVerificationContract> values) {
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
        boolean evaluationReady,
        boolean protectedRemediationReady,
        String enterpriseIntegrationState,
        boolean enterpriseIntegrationReady,
        boolean firstPartyRemediationAdapterConfigured,
        boolean enterpriseExecutionConfigured,
        boolean enterpriseVerificationConfigured,
        boolean enterpriseCredentialConfigured,
        String enterpriseExecutionHost,
        String enterpriseVerificationHost,
        boolean enterprisePolicyAllowsExecutionHost,
        boolean enterprisePolicyAllowsVerificationHost,
        boolean enterpriseExecutorDelegationAllowsExecutionHost,
        boolean enterpriseExecutorDelegationAllowsVerificationHost,
        List<String> enterpriseSupportedExecutableActions,
        List<String> enterpriseSupportedVerifiedActions,
        List<EnterpriseVerificationContract> enterpriseVerificationContracts,
        List<String> enterpriseEvaluationOnlyActions,
        String enterpriseIntegrationCheckedAt,
        String delegationMemberState,
        String delegationEffectiveState,
        List<String> delegatedFunctions,
        List<String> delegatedScopes,
        List<String> allowedHosts,
        List<String> delegationCheckedFunctions,
        List<String> delegationCheckedScopes,
        String executorDelegationMemberState,
        String executorDelegationEffectiveState,
        List<String> executorDelegatedFunctions,
        List<String> executorDelegatedScopes,
        List<String> executorAllowedHosts,
        List<String> executorDelegationCheckedFunctions,
        List<String> executorDelegationCheckedScopes,
        String message
    ) {}
}
