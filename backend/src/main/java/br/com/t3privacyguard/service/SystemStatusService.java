package br.com.t3privacyguard.service;

import br.com.t3privacyguard.integration.RuntimeStatusClient;
import br.com.t3privacyguard.integration.RuntimeStatusClient.AgentRegistrationStatus;
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
import org.springframework.stereotype.Service;

@Service
public class SystemStatusService {
    private static final List<String> REGISTRATION_STATES = List.of("REGISTERED", "NOT_REGISTERED", "MISMATCH", "UNAVAILABLE");
    private final RuntimeStatusClient runtime;
    private final SecurityRemediationCredential remediationCredential;

    public SystemStatusService(RuntimeStatusClient runtime, SecurityRemediationCredential remediationCredential) {
        this.runtime = runtime;
        this.remediationCredential = remediationCredential;
    }

    public SystemStatusResponse status() {
        boolean runtimeReachable = runtime.health();
        Optional<TenantStatus> tenant = runtime.tenantStatus();
        Optional<AgentStatus> agent = runtime.agentStatus();
        Optional<ExecutorStatus> executor = runtime.executorStatus();
        Optional<AgentRegistrationStatus> registration = runtimeReachable ? runtime.agentRegistration() : Optional.empty();
        Optional<EnterpriseIntegrationReadiness> enterpriseIntegration = runtimeReachable ? runtime.enterpriseIntegrationReadiness() : Optional.empty();
        Optional<ContractIdentity> contract = runtime.contractIdentity();
        Optional<DelegationStatus> proposalDelegation = contract.flatMap(value -> runtime.delegationStatus(value.contractId()));
        Optional<DelegationStatus> executorDelegation = contract.flatMap(value -> runtime.executorDelegationStatus(value.contractId()));

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
        String enterpriseIntegrationDiagnosticCode = enterpriseIntegration
            .map(EnterpriseIntegrationReadiness::diagnosticCode)
            .orElse("TRUST_RUNTIME_UNAVAILABLE");
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
            runtimeReachable,
            delegationMemberState,
            delegationEffectiveState,
            executorDelegationMemberState,
            executorDelegationEffectiveState,
            evaluationReady,
            protectedRemediationReady
        );

        return new SystemStatusResponse(
            runtimeReachable,
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
            enterpriseIntegrationDiagnosticCode,
            enterpriseIntegrationReady,
            remediationCredential.isConfigured(),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::executionConfigured).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::verificationConfigured).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::credentialConfigured).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::executionHost).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::verificationHost).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::policyAllowsExecutionHost).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::policyAllowsVerificationHost).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::executorDelegationAllowsExecutionHost).orElse(null),
            enterpriseIntegration.map(EnterpriseIntegrationReadiness::executorDelegationAllowsVerificationHost).orElse(null),
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
        boolean runtimeReachable,
        String proposalMemberState,
        String proposalEffectiveState,
        String executorMemberState,
        String executorEffectiveState,
        boolean evaluationReady,
        boolean protectedRemediationReady
    ) {
        if (!runtimeReachable) return "guard-runtime is unreachable; evaluation and remediation fail closed.";
        if ("UNKNOWN".equals(proposalMemberState)) return "The proposal agent's grant could not be confirmed; policy evaluation remains unavailable.";
        if (!"ACTIVE".equals(proposalMemberState)) return "guard-runtime does not recognize the proposal agent credential; policy evaluation is not ready.";
        if ("DENIED".equals(proposalEffectiveState)) return "The proposal agent is known to guard-runtime but is not granted evaluate-action.";
        if (!"ACTIVE".equals(proposalEffectiveState)) return "The proposal agent's effective access could not be confirmed; policy evaluation remains unavailable.";
        if (evaluationReady && "UNKNOWN".equals(executorMemberState)) {
            return "Policy evaluation is ready, but the protected executor's grant could not be confirmed; protected remediation remains unavailable.";
        }
        if (evaluationReady && !"ACTIVE".equals(executorMemberState)) {
            return "Policy evaluation is ready, but guard-runtime does not recognize the protected executor credential; protected remediation remains unavailable.";
        }
        if (evaluationReady && "DENIED".equals(executorEffectiveState)) {
            return "Policy evaluation is ready, but the protected executor is not granted execute-remediation and verify-remediation.";
        }
        if (evaluationReady && !"ACTIVE".equals(executorEffectiveState)) {
            return "Policy evaluation is ready, but the protected executor's effective access could not be confirmed.";
        }
        if (protectedRemediationReady) {
            return "guard-runtime controls are ready: effective Proposal and Protected Executor access is confirmed for the exact functions each role needs.";
        }
        return "guard-runtime is online, but one or more identity, policy or grant checks are not confirmed as ready.";
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
        String enterpriseIntegrationDiagnosticCode,
        boolean enterpriseIntegrationReady,
        boolean firstPartyRemediationAdapterConfigured,
        Boolean enterpriseExecutionConfigured,
        Boolean enterpriseVerificationConfigured,
        Boolean enterpriseCredentialConfigured,
        String enterpriseExecutionHost,
        String enterpriseVerificationHost,
        Boolean enterprisePolicyAllowsExecutionHost,
        Boolean enterprisePolicyAllowsVerificationHost,
        Boolean enterpriseExecutorDelegationAllowsExecutionHost,
        Boolean enterpriseExecutorDelegationAllowsVerificationHost,
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
