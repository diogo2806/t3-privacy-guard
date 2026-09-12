package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.ApiModels.RemediationExecutionResponse;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RemediationQueryService {
    private final ActionProposalRepository actions;
    private final RemediationExecutionRepository executions;

    public RemediationQueryService(ActionProposalRepository actions, RemediationExecutionRepository executions) {
        this.actions = actions;
        this.executions = executions;
    }

    @Transactional(readOnly = true)
    public RemediationExecutionResponse get(String incidentId, String actionId) {
        ActionProposalEntity action = actions.findById(actionId)
            .orElseThrow(() -> new IncidentNotFoundException("Action proposal not found"));
        if (!action.getIncidentId().equals(incidentId)) {
            throw new IncidentNotFoundException("Action proposal not found for incident");
        }
        RemediationExecutionEntity execution = executions.findByActionProposalId(actionId)
            .orElseThrow(() -> new IncidentNotFoundException("Remediation execution not found"));
        return new RemediationExecutionResponse(
            incidentId,
            actionId,
            execution.getRequestId(),
            execution.getStatus().name(),
            execution.getHttpCode(),
            execution.getOperationId(),
            execution.getVerificationAttempts(),
            execution.getFailureCode(),
            execution.getStartedAt(),
            execution.getCompletedAt()
        );
    }
}
