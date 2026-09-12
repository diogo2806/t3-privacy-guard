package br.com.t3privacyguard.service;

import br.com.t3privacyguard.domain.RemediationStatus;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RemediationExecutionCoordinator {
    private final ActionProposalRepository actions;
    private final RemediationExecutionRepository executions;

    public RemediationExecutionCoordinator(ActionProposalRepository actions, RemediationExecutionRepository executions) {
        this.actions = actions;
        this.executions = executions;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ClaimResult claim(String actionId, String requestId) {
        actions.findByIdForExecutionClaim(actionId)
            .orElseThrow(() -> new IncidentNotFoundException("Action proposal not found"));
        Optional<RemediationExecutionEntity> existing = executions.findByActionProposalId(actionId);
        if (existing.isPresent()) return new ClaimResult(false, existing.get());

        RemediationExecutionEntity created = executions.saveAndFlush(new RemediationExecutionEntity(
            UUID.randomUUID().toString(), actionId, requestId, Instant.now()
        ));
        return new ClaimResult(true, created);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public RemediationExecutionEntity markPendingVerification(String actionId, int httpCode, String operationId) {
        RemediationExecutionEntity entity = require(actionId);
        entity.markPendingVerification(httpCode, operationId, Instant.now());
        return executions.saveAndFlush(entity);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public RemediationExecutionEntity markVerificationAttempt(String actionId) {
        RemediationExecutionEntity entity = require(actionId);
        entity.markVerificationAttempt(Instant.now());
        return executions.saveAndFlush(entity);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public RemediationExecutionEntity markCompleted(String actionId) {
        RemediationExecutionEntity entity = require(actionId);
        entity.markCompleted(Instant.now());
        return executions.saveAndFlush(entity);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public RemediationExecutionEntity markUnverified(String actionId, String failureCode) {
        RemediationExecutionEntity entity = require(actionId);
        entity.markUnverified(safeCode(failureCode), Instant.now());
        return executions.saveAndFlush(entity);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public RemediationExecutionEntity markFailed(String actionId, String failureCode) {
        RemediationExecutionEntity entity = require(actionId);
        entity.markFailed(safeCode(failureCode), Instant.now());
        return executions.saveAndFlush(entity);
    }

    @Transactional(readOnly = true)
    public Optional<RemediationExecutionEntity> find(String actionId) {
        return executions.findByActionProposalId(actionId);
    }

    private RemediationExecutionEntity require(String actionId) {
        return executions.findByActionProposalId(actionId)
            .orElseThrow(() -> new IncidentNotFoundException("Remediation execution not found"));
    }

    private String safeCode(String value) {
        String normalized = value == null ? "UNKNOWN" : value.replaceAll("[^A-Z0-9_-]", "_").toUpperCase();
        return normalized.substring(0, Math.min(normalized.length(), 120));
    }

    public record ClaimResult(boolean acquired, RemediationExecutionEntity execution) {
        public boolean completed() { return execution.getStatus() == RemediationStatus.COMPLETED; }
    }
}
