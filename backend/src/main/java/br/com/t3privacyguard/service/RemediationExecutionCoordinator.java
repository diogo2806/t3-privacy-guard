package br.com.t3privacyguard.service;

import br.com.t3privacyguard.audit.AuditIntegrityService;
import br.com.t3privacyguard.domain.RemediationStatus;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RemediationExecutionCoordinator {
    private static final Duration EXECUTION_STALE_AFTER = Duration.ofMinutes(2);

    private final ActionProposalRepository actions;
    private final RemediationExecutionRepository executions;
    private final AuditIntegrityService auditIntegrity;

    public RemediationExecutionCoordinator(
        ActionProposalRepository actions,
        RemediationExecutionRepository executions,
        AuditIntegrityService auditIntegrity
    ) {
        this.actions = actions;
        this.executions = executions;
        this.auditIntegrity = auditIntegrity;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public ClaimResult claim(String actionId, String requestId) {
        ActionProposalEntity action = actions.findByIdForExecutionClaim(actionId)
            .orElseThrow(() -> new IncidentNotFoundException("Action proposal not found"));
        Optional<RemediationExecutionEntity> existing = executions.findByActionProposalId(actionId);
        if (existing.isPresent()) return new ClaimResult(false, existing.get());

        String executionPrincipal = currentAuthenticatedPrincipal();
        RemediationExecutionEntity created = executions.saveAndFlush(new RemediationExecutionEntity(
            UUID.randomUUID().toString(), actionId, requestId, Instant.now(), executionPrincipal
        ));
        if (executionPrincipal != null) {
            auditIntegrity.append(
                action.getIncidentId(),
                "REMEDIATION_EXECUTION_STARTED",
                "EXECUTOR principal " + executionPrincipal + " started protected execution for request " + requestId
            );
        }
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
        Instant now = Instant.now();
        if ("RECOVERY_EXECUTION_OUTCOME_UNKNOWN".equals(failureCode)
            && entity.getStatus() == RemediationStatus.EXECUTING
            && entity.getStartedAt().plus(EXECUTION_STALE_AFTER).isAfter(now)) {
            return entity;
        }
        entity.markUnverified(safeCode(failureCode), now);
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

    private static String currentAuthenticatedPrincipal() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) return null;
        try {
            return ActionProposalEntity.canonicalizeAuthenticatedPrincipal(authentication.getName());
        } catch (IllegalArgumentException exception) {
            return null;
        }
    }

    public record ClaimResult(boolean acquired, RemediationExecutionEntity execution) {
        public boolean completed() { return execution.getStatus() == RemediationStatus.COMPLETED; }
    }
}
