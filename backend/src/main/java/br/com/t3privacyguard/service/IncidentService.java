package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.ApiModels.ActionResponse;
import br.com.t3privacyguard.api.ApiModels.AuditResponse;
import br.com.t3privacyguard.api.ApiModels.CreateActionRequest;
import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.api.ApiModels.DecisionResponse;
import br.com.t3privacyguard.api.ApiModels.IncidentResponse;
import br.com.t3privacyguard.api.ApiModels.RemediationAuthorizationResponse;
import br.com.t3privacyguard.api.ApiModels.RemediationExecutionResponse;
import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.ProposalStatus;
import br.com.t3privacyguard.domain.RemediationStatus;
import br.com.t3privacyguard.integration.GatewayPolicyClient;
import br.com.t3privacyguard.integration.GatewayPolicyClient.GatewayEvaluationRequest;
import br.com.t3privacyguard.integration.GatewayRemediationClient;
import br.com.t3privacyguard.integration.GatewayRemediationClient.RemediationRequest;
import br.com.t3privacyguard.integration.GatewayUnavailableException;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionEntity;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.security.RemediationAuthorizationSigner;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IncidentService {
    private final IncidentRepository incidents;
    private final ActionProposalRepository actions;
    private final PolicyDecisionRepository decisions;
    private final AuditEventRepository audits;
    private final GatewayPolicyClient gateway;
    private final GatewayRemediationClient remediationGateway;
    private final RemediationAuthorizationSigner remediationAuthorizationSigner;
    private final RemediationExecutionCoordinator executionCoordinator;
    private final ObjectMapper mapper;

    public IncidentService(
        IncidentRepository incidents,
        ActionProposalRepository actions,
        PolicyDecisionRepository decisions,
        AuditEventRepository audits,
        GatewayPolicyClient gateway,
        GatewayRemediationClient remediationGateway,
        RemediationAuthorizationSigner remediationAuthorizationSigner,
        RemediationExecutionCoordinator executionCoordinator,
        ObjectMapper mapper
    ) {
        this.incidents = incidents;
        this.actions = actions;
        this.decisions = decisions;
        this.audits = audits;
        this.gateway = gateway;
        this.remediationGateway = remediationGateway;
        this.remediationAuthorizationSigner = remediationAuthorizationSigner;
        this.executionCoordinator = executionCoordinator;
        this.mapper = mapper;
    }

    @Transactional
    public IncidentResponse createIncident(CreateIncidentRequest request) {
        Instant now = Instant.now();
        IncidentEntity entity = incidents.save(new IncidentEntity(
            UUID.randomUUID().toString(), request.title().trim(), request.severity(), request.summary().trim(), request.source().trim(), now
        ));
        audit(entity.getId(), "INCIDENT_CREATED", "Incident created with severity " + entity.getSeverity());
        return incidentResponse(entity);
    }

    @Transactional(readOnly = true)
    public List<IncidentResponse> listIncidents() {
        return incidents.findAll().stream().sorted(Comparator.comparing(IncidentEntity::getCreatedAt).reversed()).map(this::incidentResponse).toList();
    }

    @Transactional(readOnly = true)
    public IncidentResponse getIncident(String id) { return incidentResponse(requireIncident(id)); }

    @Transactional
    public ActionResponse addAction(String incidentId, CreateActionRequest request) {
        requireIncident(incidentId);
        String requestId = request.requestId().trim();
        if (actions.findByRequestId(requestId).isPresent()) throw new ConflictException("requestId already exists; duplicate/replay rejected");
        List<String> privateRefs = request.privateRefs() == null ? List.of() : request.privateRefs();
        validateLogicalPrivateRefs(privateRefs);
        try {
            ActionProposalEntity entity = actions.saveAndFlush(new ActionProposalEntity(
                UUID.randomUUID().toString(), incidentId, requestId, request.action().trim(), request.resource().trim(), request.purpose().trim(),
                blankToNull(request.host()), writeJson(request.fields()), writeJson(privateRefs), Instant.now()
            ));
            audit(incidentId, "ACTION_PROPOSED", "Action " + entity.getAction() + " proposed as request " + requestId);
            return actionResponse(entity);
        } catch (DataIntegrityViolationException ex) {
            throw new ConflictException("requestId already exists; duplicate/replay rejected");
        }
    }

    @Transactional(readOnly = true)
    public List<ActionResponse> listActions(String incidentId) {
        requireIncident(incidentId);
        return actions.findByIncidentIdOrderByCreatedAtAsc(incidentId).stream().map(this::actionResponse).toList();
    }

    @Transactional
    public DecisionResponse evaluate(String incidentId, String actionId) {
        ActionProposalEntity action = requireAction(incidentId, actionId);
        Optional<PolicyDecisionEntity> existing = decisions.findByActionProposalId(actionId);
        if (existing.isPresent()) return decisionResponse(existing.get());

        var gatewayDecision = gateway.evaluate(new GatewayEvaluationRequest(
            action.getRequestId(), action.getAction(), action.getResource(), action.getPurpose(), action.getHost(),
            readList(action.getFieldsJson()), readList(action.getPrivateRefsJson())
        ));
        if (!action.getRequestId().equals(gatewayDecision.requestId())) throw new IllegalStateException("Policy decision request id mismatch");

        PolicyDecisionEntity entity = decisions.save(new PolicyDecisionEntity(
            UUID.randomUUID().toString(), actionId, gatewayDecision.decision(), safe(gatewayDecision.reasonCode(), 80), safe(gatewayDecision.reason(), 800),
            writeJson(gatewayDecision.allowedFields()), writeJson(gatewayDecision.redactedFields()),
            writeJson(gatewayDecision.allowedPrivateRefs()), writeJson(gatewayDecision.redactedPrivateRefs()), Instant.now()
        ));
        action.markEvaluated();
        actions.save(action);
        audit(incidentId, "POLICY_DECISION", "Policy decision " + entity.getDecision() + " with reason " + entity.getReasonCode());
        return decisionResponse(entity);
    }

    @Transactional(readOnly = true)
    public DecisionResponse getDecision(String incidentId, String actionId) {
        requireAction(incidentId, actionId);
        return decisionResponse(decisions.findByActionProposalId(actionId).orElseThrow(() -> new IncidentNotFoundException("Policy decision not found")));
    }

    @Transactional
    public RemediationAuthorizationResponse authorizeRemediation(String incidentId, String actionId) {
        ActionProposalEntity action = requireAction(incidentId, actionId);
        PolicyDecisionEntity decision = decisions.findByActionProposalId(actionId).orElseThrow(() -> new ConflictException("Action must be evaluated before remediation"));
        if (decision.getDecision() != DecisionType.ALLOW) throw new PolicyDeniedException("Remediation requires an ALLOW policy decision");
        action.authorizeRemediation();
        actions.save(action);
        audit(incidentId, "REMEDIATION_AUTHORIZED", "Remediation authorized for request " + action.getRequestId());
        return new RemediationAuthorizationResponse(incidentId, actionId, action.getRequestId(), action.getStatus().name());
    }

    public RemediationExecutionResponse executeRemediation(String incidentId, String actionId) {
        ActionProposalEntity action = requireAction(incidentId, actionId);
        if (action.getStatus() != ProposalStatus.REMEDIATION_AUTHORIZED && action.getStatus() != ProposalStatus.REMEDIATED) {
            throw new PolicyDeniedException("Remediation must be explicitly authorized before execution");
        }
        PolicyDecisionEntity decision = decisions.findByActionProposalId(actionId)
            .orElseThrow(() -> new ConflictException("A persisted policy decision is required before remediation"));
        if (decision.getDecision() != DecisionType.ALLOW) throw new PolicyDeniedException("Remediation requires a persisted ALLOW policy decision");

        RemediationExecutionCoordinator.ClaimResult claim = executionCoordinator.claim(actionId, action.getRequestId());
        if (!claim.acquired()) return reconcileExisting(incidentId, action, claim.execution());

        List<String> fields = readList(action.getFieldsJson());
        List<String> privateRefs = readList(action.getPrivateRefsJson());
        String capability = remediationAuthorizationSigner.issue(
            incidentId, actionId, action.getRequestId(), decision.getId(), action.getAction(), action.getResource(), action.getPurpose(), fields, privateRefs
        );

        try {
            var result = remediationGateway.execute(new RemediationRequest(
                incidentId, actionId, decision.getId(), action.getRequestId(), action.getAction(), action.getResource(), action.getPurpose(), fields, privateRefs
            ), capability);
            if (!action.getRequestId().equals(result.requestId())) {
                RemediationExecutionEntity state = executionCoordinator.markUnverified(actionId, "REQUEST_ID_MISMATCH");
                audit(incidentId, "REMEDIATION_UNVERIFIED", "Execution acknowledgement request id did not match; no automatic retry will occur");
                return remediationResponse(incidentId, actionId, state);
            }
            RemediationExecutionEntity pending = executionCoordinator.markPendingVerification(actionId, result.httpCode(), safeNullable(result.operationId(), 200));
            audit(incidentId, "REMEDIATION_ACCEPTED", "External request accepted; independent verification is required before completion");
            return verifyPersistedRemediation(incidentId, action, pending);
        } catch (GatewayUnavailableException ex) {
            RemediationExecutionEntity state = executionCoordinator.markUnverified(actionId, "EXECUTION_RESULT_UNKNOWN");
            audit(incidentId, "REMEDIATION_UNVERIFIED", "Execution outcome is ambiguous; automatic re-execution is blocked");
            return remediationResponse(incidentId, actionId, state);
        }
    }

    public RemediationExecutionResponse verifyRemediation(String incidentId, String actionId) {
        ActionProposalEntity action = requireAction(incidentId, actionId);
        RemediationExecutionEntity execution = executionCoordinator.find(actionId)
            .orElseThrow(() -> new ConflictException("Remediation has not been started"));
        return reconcileExisting(incidentId, action, execution);
    }

    private RemediationExecutionResponse reconcileExisting(String incidentId, ActionProposalEntity action, RemediationExecutionEntity execution) {
        if (execution.getStatus() == RemediationStatus.COMPLETED || execution.getStatus() == RemediationStatus.FAILED) {
            return remediationResponse(incidentId, action.getId(), execution);
        }
        if (execution.getStatus() == RemediationStatus.EXECUTING && execution.getOperationId() == null) {
            RemediationExecutionEntity state = executionCoordinator.markUnverified(action.getId(), "RECOVERY_EXECUTION_OUTCOME_UNKNOWN");
            audit(incidentId, "REMEDIATION_UNVERIFIED", "Recovered an execution claim without a verifiable operation id; no automatic retry will occur");
            return remediationResponse(incidentId, action.getId(), state);
        }
        return verifyPersistedRemediation(incidentId, action, execution);
    }

    private RemediationExecutionResponse verifyPersistedRemediation(String incidentId, ActionProposalEntity action, RemediationExecutionEntity execution) {
        if (execution.getOperationId() == null || execution.getOperationId().isBlank()) {
            RemediationExecutionEntity state = executionCoordinator.markUnverified(action.getId(), "MISSING_OPERATION_ID");
            audit(incidentId, "REMEDIATION_UNVERIFIED", "External acknowledgement did not provide an operation id for independent verification");
            return remediationResponse(incidentId, action.getId(), state);
        }

        executionCoordinator.markVerificationAttempt(action.getId());
        try {
            var verification = remediationGateway.verify(execution.getRequestId(), execution.getOperationId());
            if (!execution.getRequestId().equals(verification.requestId())) {
                RemediationExecutionEntity state = executionCoordinator.markUnverified(action.getId(), "VERIFICATION_REQUEST_ID_MISMATCH");
                return remediationResponse(incidentId, action.getId(), state);
            }
            if ("VERIFIED".equals(verification.status()) && "REVOKED".equals(verification.observedState())) {
                RemediationExecutionEntity completed = executionCoordinator.markCompleted(action.getId());
                action.markRemediated();
                actions.save(action);
                audit(incidentId, "REMEDIATION_VERIFIED", "Independent read-back confirmed expected external state REVOKED");
                return remediationResponse(incidentId, action.getId(), completed);
            }
            RemediationExecutionEntity state = executionCoordinator.markUnverified(action.getId(), "EXTERNAL_STATE_NOT_VERIFIED");
            audit(incidentId, "REMEDIATION_UNVERIFIED", "Independent read-back did not confirm the expected external state");
            return remediationResponse(incidentId, action.getId(), state);
        } catch (GatewayUnavailableException ex) {
            RemediationExecutionEntity state = executionCoordinator.markUnverified(action.getId(), "VERIFICATION_UNAVAILABLE");
            audit(incidentId, "REMEDIATION_UNVERIFIED", "External verification is unavailable; no automatic re-execution will occur");
            return remediationResponse(incidentId, action.getId(), state);
        }
    }

    @Transactional(readOnly = true)
    public List<AuditResponse> history(String incidentId) {
        requireIncident(incidentId);
        return audits.findByIncidentIdOrderByCreatedAtAsc(incidentId).stream()
            .map(event -> new AuditResponse(event.getId(), event.getIncidentId(), event.getType(), event.getMessage(), event.getCreatedAt())).toList();
    }

    private IncidentEntity requireIncident(String id) { return incidents.findById(id).orElseThrow(() -> new IncidentNotFoundException("Incident not found")); }

    private ActionProposalEntity requireAction(String incidentId, String id) {
        ActionProposalEntity action = actions.findById(id).orElseThrow(() -> new IncidentNotFoundException("Action proposal not found"));
        if (!action.getIncidentId().equals(incidentId)) throw new IncidentNotFoundException("Action proposal not found for incident");
        return action;
    }

    private void validateLogicalPrivateRefs(List<String> refs) {
        for (String ref : refs) {
            String normalized = ref == null ? "" : ref.trim().toLowerCase();
            if (!"verified_email".equals(normalized)) throw new IllegalArgumentException("Only the logical private reference verified_email is supported; plaintext and T3N placeholder strings are not accepted");
        }
    }

    private void audit(String incidentId, String type, String message) {
        audits.save(new AuditEventEntity(UUID.randomUUID().toString(), incidentId, type, safe(message, 600), Instant.now()));
    }

    private IncidentResponse incidentResponse(IncidentEntity entity) {
        return new IncidentResponse(entity.getId(), entity.getTitle(), entity.getSeverity(), entity.getSummary(), entity.getSource(), entity.getStatus(), entity.getCreatedAt());
    }

    private ActionResponse actionResponse(ActionProposalEntity entity) {
        return new ActionResponse(
            entity.getId(), entity.getIncidentId(), entity.getRequestId(), entity.getAction(), entity.getResource(), entity.getPurpose(), entity.getHost(),
            readList(entity.getFieldsJson()), readList(entity.getPrivateRefsJson()), entity.getStatus(), entity.getCreatedAt()
        );
    }

    private DecisionResponse decisionResponse(PolicyDecisionEntity entity) {
        return new DecisionResponse(
            entity.getId(), entity.getActionProposalId(), entity.getDecision(), entity.getReasonCode(), entity.getReason(),
            readList(entity.getAllowedFieldsJson()), readList(entity.getRedactedFieldsJson()),
            readList(entity.getAllowedPrivateRefsJson()), readList(entity.getRedactedPrivateRefsJson()), entity.getEvaluatedAt()
        );
    }

    private RemediationExecutionResponse remediationResponse(String incidentId, String actionId, RemediationExecutionEntity entity) {
        return new RemediationExecutionResponse(
            incidentId, actionId, entity.getRequestId(), entity.getStatus().name(), entity.getHttpCode(), entity.getOperationId(),
            entity.getVerificationAttempts(), entity.getFailureCode(), entity.getStartedAt(), entity.getCompletedAt()
        );
    }

    private String writeJson(Object value) {
        try { return mapper.writeValueAsString(value == null ? List.of() : value); }
        catch (JsonProcessingException ex) { throw new IllegalArgumentException("Unable to encode request metadata", ex); }
    }

    private List<String> readList(String json) {
        try { return mapper.readValue(json, new TypeReference<List<String>>() {}); }
        catch (JsonProcessingException ex) { throw new IllegalStateException("Stored metadata is invalid", ex); }
    }

    private static String blankToNull(String value) { return value == null || value.isBlank() ? null : value.trim(); }
    private static String safe(String value, int max) {
        String result = value == null ? "" : value.replaceAll("(?i)(api[_-]?key|password|private[_-]?key|token)\\s*[:=]\\s*\\S+", "$1=[REDACTED]");
        return result.substring(0, Math.min(result.length(), max));
    }
    private static String safeNullable(String value, int max) { return value == null ? null : safe(value, max); }
}
