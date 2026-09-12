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
import br.com.t3privacyguard.integration.GatewayPolicyClient;
import br.com.t3privacyguard.integration.GatewayPolicyClient.GatewayEvaluationRequest;
import br.com.t3privacyguard.integration.GatewayRemediationClient;
import br.com.t3privacyguard.integration.GatewayRemediationClient.RemediationRequest;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionEntity;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
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
    private final RemediationExecutionRepository remediations;
    private final GatewayPolicyClient gateway;
    private final GatewayRemediationClient remediationGateway;
    private final RemediationAuthorizationSigner remediationAuthorizationSigner;
    private final ObjectMapper mapper;

    public IncidentService(
        IncidentRepository incidents,
        ActionProposalRepository actions,
        PolicyDecisionRepository decisions,
        AuditEventRepository audits,
        RemediationExecutionRepository remediations,
        GatewayPolicyClient gateway,
        GatewayRemediationClient remediationGateway,
        RemediationAuthorizationSigner remediationAuthorizationSigner,
        ObjectMapper mapper
    ) {
        this.incidents = incidents;
        this.actions = actions;
        this.decisions = decisions;
        this.audits = audits;
        this.remediations = remediations;
        this.gateway = gateway;
        this.remediationGateway = remediationGateway;
        this.remediationAuthorizationSigner = remediationAuthorizationSigner;
        this.mapper = mapper;
    }

    @Transactional
    public IncidentResponse createIncident(CreateIncidentRequest request) {
        Instant now = Instant.now();
        IncidentEntity entity = incidents.save(new IncidentEntity(
            UUID.randomUUID().toString(),
            request.title().trim(),
            request.severity(),
            request.summary().trim(),
            request.source().trim(),
            now
        ));
        audit(entity.getId(), "INCIDENT_CREATED", "Incident created with severity " + entity.getSeverity());
        return incidentResponse(entity);
    }

    @Transactional(readOnly = true)
    public List<IncidentResponse> listIncidents() {
        return incidents.findAll().stream()
            .sorted(Comparator.comparing(IncidentEntity::getCreatedAt).reversed())
            .map(this::incidentResponse)
            .toList();
    }

    @Transactional(readOnly = true)
    public IncidentResponse getIncident(String id) {
        return incidentResponse(requireIncident(id));
    }

    @Transactional
    public ActionResponse addAction(String incidentId, CreateActionRequest request) {
        requireIncident(incidentId);
        String requestId = request.requestId().trim();
        if (actions.findByRequestId(requestId).isPresent()) {
            throw new ConflictException("requestId already exists; duplicate/replay rejected");
        }

        try {
            ActionProposalEntity entity = actions.saveAndFlush(new ActionProposalEntity(
                UUID.randomUUID().toString(),
                incidentId,
                requestId,
                request.action().trim(),
                request.resource().trim(),
                request.purpose().trim(),
                blankToNull(request.host()),
                writeJson(request.fields()),
                Instant.now()
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
        return actions.findByIncidentIdOrderByCreatedAtAsc(incidentId).stream()
            .map(this::actionResponse)
            .toList();
    }

    @Transactional
    public DecisionResponse evaluate(String incidentId, String actionId) {
        ActionProposalEntity action = requireAction(incidentId, actionId);
        Optional<PolicyDecisionEntity> existing = decisions.findByActionProposalId(actionId);
        if (existing.isPresent()) {
            return decisionResponse(existing.get());
        }

        var gatewayDecision = gateway.evaluate(new GatewayEvaluationRequest(
            action.getRequestId(),
            action.getAction(),
            action.getResource(),
            action.getPurpose(),
            action.getHost(),
            readList(action.getFieldsJson())
        ));
        if (!action.getRequestId().equals(gatewayDecision.requestId())) {
            throw new IllegalStateException("Policy decision request id mismatch");
        }

        PolicyDecisionEntity entity = decisions.save(new PolicyDecisionEntity(
            UUID.randomUUID().toString(),
            actionId,
            gatewayDecision.decision(),
            safe(gatewayDecision.reasonCode(), 80),
            safe(gatewayDecision.reason(), 800),
            writeJson(gatewayDecision.allowedFields()),
            writeJson(gatewayDecision.redactedFields()),
            Instant.now()
        ));
        action.markEvaluated();
        actions.save(action);
        audit(incidentId, "POLICY_DECISION", "Policy decision " + entity.getDecision() + " with reason " + entity.getReasonCode());
        return decisionResponse(entity);
    }

    @Transactional(readOnly = true)
    public DecisionResponse getDecision(String incidentId, String actionId) {
        requireAction(incidentId, actionId);
        PolicyDecisionEntity decision = decisions.findByActionProposalId(actionId)
            .orElseThrow(() -> new IncidentNotFoundException("Policy decision not found"));
        return decisionResponse(decision);
    }

    @Transactional
    public RemediationAuthorizationResponse authorizeRemediation(String incidentId, String actionId) {
        ActionProposalEntity action = requireAction(incidentId, actionId);
        PolicyDecisionEntity decision = decisions.findByActionProposalId(actionId)
            .orElseThrow(() -> new ConflictException("Action must be evaluated before remediation"));

        if (decision.getDecision() != DecisionType.ALLOW) {
            throw new PolicyDeniedException("Remediation requires an ALLOW policy decision");
        }

        action.authorizeRemediation();
        actions.save(action);
        audit(incidentId, "REMEDIATION_AUTHORIZED", "Remediation authorized for request " + action.getRequestId());
        return new RemediationAuthorizationResponse(incidentId, actionId, action.getRequestId(), action.getStatus().name());
    }

    @Transactional
    public RemediationExecutionResponse executeRemediation(String incidentId, String actionId) {
        ActionProposalEntity action = requireAction(incidentId, actionId);
        Optional<RemediationExecutionEntity> persisted = remediations.findByActionProposalId(actionId);
        if (persisted.isPresent()) {
            return remediationResponse(incidentId, actionId, persisted.get());
        }
        if (action.getStatus() != ProposalStatus.REMEDIATION_AUTHORIZED) {
            throw new PolicyDeniedException("Remediation must be explicitly authorized before execution");
        }

        PolicyDecisionEntity decision = decisions.findByActionProposalId(actionId)
            .orElseThrow(() -> new ConflictException("A persisted policy decision is required before remediation"));
        if (decision.getDecision() != DecisionType.ALLOW) {
            throw new PolicyDeniedException("Remediation requires a persisted ALLOW policy decision");
        }

        List<String> fields = readList(action.getFieldsJson());
        String capability = remediationAuthorizationSigner.issue(
            incidentId,
            actionId,
            action.getRequestId(),
            decision.getId(),
            action.getAction(),
            action.getResource(),
            action.getPurpose(),
            fields
        );
        var result = remediationGateway.execute(new RemediationRequest(
            incidentId,
            actionId,
            decision.getId(),
            action.getRequestId(),
            action.getAction(),
            action.getResource(),
            action.getPurpose(),
            fields
        ), capability);
        if (!action.getRequestId().equals(result.requestId())) {
            throw new IllegalStateException("Remediation result request id mismatch");
        }

        RemediationExecutionEntity saved = remediations.saveAndFlush(new RemediationExecutionEntity(
            UUID.randomUUID().toString(),
            actionId,
            result.requestId(),
            result.status(),
            result.httpCode(),
            safeNullable(result.operationId(), 200),
            Instant.now()
        ));
        action.markRemediated();
        actions.save(action);
        audit(incidentId, "REMEDIATION_EXECUTED", "Protected remediation completed with HTTP " + saved.getHttpCode());
        return remediationResponse(incidentId, actionId, saved);
    }

    @Transactional(readOnly = true)
    public List<AuditResponse> history(String incidentId) {
        requireIncident(incidentId);
        return audits.findByIncidentIdOrderByCreatedAtAsc(incidentId).stream()
            .map(event -> new AuditResponse(
                event.getId(), event.getIncidentId(), event.getType(), event.getMessage(), event.getCreatedAt()
            ))
            .toList();
    }

    private IncidentEntity requireIncident(String id) {
        return incidents.findById(id).orElseThrow(() -> new IncidentNotFoundException("Incident not found"));
    }

    private ActionProposalEntity requireAction(String incidentId, String id) {
        ActionProposalEntity action = actions.findById(id)
            .orElseThrow(() -> new IncidentNotFoundException("Action proposal not found"));
        if (!action.getIncidentId().equals(incidentId)) {
            throw new IncidentNotFoundException("Action proposal not found for incident");
        }
        return action;
    }

    private void audit(String incidentId, String type, String message) {
        audits.save(new AuditEventEntity(UUID.randomUUID().toString(), incidentId, type, safe(message, 600), Instant.now()));
    }

    private IncidentResponse incidentResponse(IncidentEntity entity) {
        return new IncidentResponse(entity.getId(), entity.getTitle(), entity.getSeverity(), entity.getSummary(), entity.getSource(), entity.getStatus(), entity.getCreatedAt());
    }

    private ActionResponse actionResponse(ActionProposalEntity entity) {
        return new ActionResponse(entity.getId(), entity.getIncidentId(), entity.getRequestId(), entity.getAction(), entity.getResource(), entity.getPurpose(), entity.getHost(), readList(entity.getFieldsJson()), entity.getStatus(), entity.getCreatedAt());
    }

    private DecisionResponse decisionResponse(PolicyDecisionEntity entity) {
        return new DecisionResponse(entity.getId(), entity.getActionProposalId(), entity.getDecision(), entity.getReasonCode(), entity.getReason(), readList(entity.getAllowedFieldsJson()), readList(entity.getRedactedFieldsJson()), entity.getEvaluatedAt());
    }

    private RemediationExecutionResponse remediationResponse(String incidentId, String actionId, RemediationExecutionEntity entity) {
        return new RemediationExecutionResponse(incidentId, actionId, entity.getRequestId(), ProposalStatus.REMEDIATED.name(), entity.getHttpCode(), entity.getOperationId());
    }

    private String writeJson(Object value) {
        try {
            return mapper.writeValueAsString(value == null ? List.of() : value);
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException("Unable to encode request metadata", ex);
        }
    }

    private List<String> readList(String json) {
        try {
            return mapper.readValue(json, new TypeReference<List<String>>() {});
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException("Stored metadata is invalid", ex);
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String safe(String value, int max) {
        String result = value == null ? "" : value.replaceAll("(?i)(api[_-]?key|password|private[_-]?key|token)\\s*[:=]\\s*\\S+", "$1=[REDACTED]");
        return result.substring(0, Math.min(result.length(), max));
    }

    private static String safeNullable(String value, int max) {
        return value == null ? null : safe(value, max);
    }
}
