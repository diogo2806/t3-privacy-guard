package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.ApiModels.*;
import br.com.t3privacyguard.domain.*;
import br.com.t3privacyguard.integration.GatewayPolicyClient;
import br.com.t3privacyguard.integration.GatewayPolicyClient.GatewayEvaluationRequest;
import br.com.t3privacyguard.persistence.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.*;
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
    private final ObjectMapper mapper;

    public IncidentService(IncidentRepository incidents, ActionProposalRepository actions, PolicyDecisionRepository decisions, AuditEventRepository audits, GatewayPolicyClient gateway, ObjectMapper mapper) {
        this.incidents = incidents;
        this.actions = actions;
        this.decisions = decisions;
        this.audits = audits;
        this.gateway = gateway;
        this.mapper = mapper;
    }

    @Transactional
    public IncidentResponse createIncident(CreateIncidentRequest request) {
        Instant now = Instant.now();
        IncidentEntity entity = incidents.save(new IncidentEntity(UUID.randomUUID().toString(), request.title().trim(), request.severity(), request.summary().trim(), request.source().trim(), now));
        audit(entity.getId(), "INCIDENT_CREATED", "Incident created with severity " + entity.getSeverity());
        return incidentResponse(entity);
    }

    @Transactional(readOnly = true)
    public List<IncidentResponse> listIncidents() {
        return incidents.findAll().stream().sorted(Comparator.comparing(IncidentEntity::getCreatedAt).reversed()).map(this::incidentResponse).toList();
    }

    @Transactional(readOnly = true)
    public IncidentResponse getIncident(String incidentId) { return incidentResponse(requireIncident(incidentId)); }

    @Transactional
    public ActionResponse addAction(String incidentId, CreateActionRequest request) {
        requireIncident(incidentId);
        if (actions.findByRequestId(request.requestId().trim()).isPresent()) throw new ConflictException("requestId already exists; duplicate/replay rejected");
        try {
            ActionProposalEntity entity = actions.saveAndFlush(new ActionProposalEntity(
                UUID.randomUUID().toString(), incidentId, request.requestId().trim(), request.action().trim(), request.resource().trim(), request.purpose().trim(), blankToNull(request.host()), writeJson(request.fields()), Instant.now()));
            audit(incidentId, "ACTION_PROPOSED", "Action " + entity.getAction() + " proposed as request " + entity.getRequestId());
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

        List<String> fields = readList(action.getFieldsJson());
        var gatewayDecision = gateway.evaluate(new GatewayEvaluationRequest(action.getRequestId(), action.getAction(), action.getResource(), action.getPurpose(), action.getHost(), fields));
        if (!action.getRequestId().equals(gatewayDecision.requestId())) throw new IllegalStateException("Policy decision request id mismatch");

        PolicyDecisionEntity entity = decisions.save(new PolicyDecisionEntity(
            UUID.randomUUID().toString(), actionId, gatewayDecision.decision(), safe(gatewayDecision.reasonCode(), 80), safe(gatewayDecision.reason(), 800), writeJson(gatewayDecision.allowedFields()), writeJson(gatewayDecision.redactedFields()), Instant.now()));
        action.markEvaluated();
        actions.save(action);
        audit(incidentId, "POLICY_DECISION", "Policy decision " + entity.getDecision() + " with reason " + entity.getReasonCode());
        return decisionResponse(entity);
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

    @Transactional(readOnly = true)
    public List<AuditResponse> history(String incidentId) {
        requireIncident(incidentId);
        return audits.findByIncidentIdOrderByCreatedAtAsc(incidentId).stream().map(event -> new AuditResponse(event.getId(), event.getIncidentId(), event.getType(), event.getMessage(), event.getCreatedAt())).toList();
    }

    private IncidentEntity requireIncident(String id) { return incidents.findById(id).orElseThrow(() -> new IncidentNotFoundException("Incident not found")); }
    private ActionProposalEntity requireAction(String incidentId, String actionId) {
        ActionProposalEntity action = actions.findById(actionId).orElseThrow(() -> new IncidentNotFoundException("Action proposal not found"));
        if (!action.getIncidentId().equals(incidentId)) throw new IncidentNotFoundException("Action proposal not found for incident");
        return action;
    }
    private void audit(String incidentId, String type, String message) { audits.save(new AuditEventEntity(UUID.randomUUID().toString(), incidentId, type, safe(message, 600), Instant.now())); }
    private IncidentResponse incidentResponse(IncidentEntity e) { return new IncidentResponse(e.getId(), e.getTitle(), e.getSeverity(), e.getSummary(), e.getSource(), e.getStatus(), e.getCreatedAt()); }
    private ActionResponse actionResponse(ActionProposalEntity e) { return new ActionResponse(e.getId(), e.getIncidentId(), e.getRequestId(), e.getAction(), e.getResource(), e.getPurpose(), e.getHost(), readList(e.getFieldsJson()), e.getStatus(), e.getCreatedAt()); }
    private DecisionResponse decisionResponse(PolicyDecisionEntity e) { return new DecisionResponse(e.getId(), e.getActionProposalId(), e.getDecision(), e.getReasonCode(), e.getReason(), readList(e.getAllowedFieldsJson()), readList(e.getRedactedFieldsJson()), e.getEvaluatedAt()); }
    private String writeJson(Object value) { try { return mapper.writeValueAsString(value == null ? List.of() : value); } catch (JsonProcessingException ex) { throw new IllegalArgumentException("Unable to encode request metadata", ex); } }
    private List<String> readList(String json) { try { return mapper.readValue(json, new TypeReference<List<String>>() {}); } catch (JsonProcessingException ex) { throw new IllegalStateException("Stored metadata is invalid", ex); } }
    private static String blankToNull(String value) { return value == null || value.isBlank() ? null : value.trim(); }
    private static String safe(String value, int max) { String result = value == null ? "" : value.replaceAll("(?i)(api[_-]?key|password|private[_-]?key|token)\\s*[:=]\\s*\\S+", "$1=[REDACTED]"); return result.substring(0, Math.min(result.length(), max)); }
}
