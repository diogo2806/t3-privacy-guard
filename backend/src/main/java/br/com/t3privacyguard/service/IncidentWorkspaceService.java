package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.IncidentWorkspaceModels.IncidentWorkspaceItem;
import br.com.t3privacyguard.api.IncidentWorkspaceModels.IncidentWorkspaceResponse;
import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.ProposalStatus;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionEntity;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IncidentWorkspaceService {
    private static final String REVOKE_CREDENTIAL = "revoke-credential";
    private static final String NOTIFY_SECURITY = "notify-security";
    private static final Set<String> PROTECTED_EXECUTION_ACTIONS = Set.of(REVOKE_CREDENTIAL, NOTIFY_SECURITY);
    private static final Set<String> REVOKE_REQUIRED_FIELDS = Set.of("incident_id", "credential_id", "reason");
    private static final Set<String> NOTIFY_REQUIRED_FIELDS = Set.of("incident_id", "severity", "summary");

    private final IncidentRepository incidents;
    private final ActionProposalRepository actions;
    private final PolicyDecisionRepository decisions;
    private final RemediationExecutionRepository remediations;
    private final ObjectMapper mapper;

    public IncidentWorkspaceService(
        IncidentRepository incidents,
        ActionProposalRepository actions,
        PolicyDecisionRepository decisions,
        RemediationExecutionRepository remediations,
        ObjectMapper mapper
    ) {
        this.incidents = incidents;
        this.actions = actions;
        this.decisions = decisions;
        this.remediations = remediations;
        this.mapper = mapper;
    }

    @Transactional(readOnly = true)
    public IncidentWorkspaceResponse getWorkspace() {
        Instant now = Instant.now();
        List<IncidentEntity> activeIncidents = incidents.findByExpiresAtAfterOrderByCreatedAtDesc(now);
        if (activeIncidents.isEmpty()) return new IncidentWorkspaceResponse(now, 0, List.of());

        List<String> incidentIds = activeIncidents.stream().map(IncidentEntity::getId).toList();
        List<ActionProposalEntity> allActions = actions.findByIncidentIdInOrderByCreatedAtAsc(incidentIds);

        Map<String, ActionProposalEntity> latestActionByIncident = new LinkedHashMap<>();
        for (ActionProposalEntity action : allActions) latestActionByIncident.put(action.getIncidentId(), action);

        List<String> latestActionIds = latestActionByIncident.values().stream().map(ActionProposalEntity::getId).toList();
        Map<String, PolicyDecisionEntity> decisionByAction = latestActionIds.isEmpty()
            ? Map.of()
            : decisions.findByActionProposalIdIn(latestActionIds).stream()
                .collect(Collectors.toMap(PolicyDecisionEntity::getActionProposalId, Function.identity()));
        Map<String, RemediationExecutionEntity> remediationByAction = latestActionIds.isEmpty()
            ? Map.of()
            : remediations.findByActionProposalIdIn(latestActionIds).stream()
                .collect(Collectors.toMap(RemediationExecutionEntity::getActionProposalId, Function.identity()));

        List<IncidentWorkspaceItem> items = new ArrayList<>(activeIncidents.size());
        long attentionCount = 0;
        for (IncidentEntity incident : activeIncidents) {
            ActionProposalEntity action = latestActionByIncident.get(incident.getId());
            PolicyDecisionEntity decision = action == null ? null : decisionByAction.get(action.getId());
            RemediationExecutionEntity remediation = action == null ? null : remediationByAction.get(action.getId());
            OperationalState state = derive(action, decision, remediation);
            if (state.requiresAttention) attentionCount++;
            items.add(new IncidentWorkspaceItem(
                incident.getId(),
                incident.getTitle(),
                incident.getSeverity(),
                incident.getSource(),
                incident.getOriginType(),
                incident.getStatus(),
                incident.getCreatedAt(),
                action == null ? null : action.getId(),
                action == null ? null : action.getAction(),
                action == null ? null : action.getStatus(),
                decision == null ? null : decision.getDecision(),
                remediation == null ? null : remediation.getStatus(),
                state.stage,
                state.nextAction,
                state.requiresAttention
            ));
        }
        return new IncidentWorkspaceResponse(now, attentionCount, List.copyOf(items));
    }

    private OperationalState derive(
        ActionProposalEntity action,
        PolicyDecisionEntity decision,
        RemediationExecutionEntity remediation
    ) {
        if (action == null) return state("NEEDS_ANALYSIS", "Analyze incident", true);

        if (remediation != null) {
            return switch (remediation.getStatus()) {
                case EXECUTING -> state("EXECUTION_IN_PROGRESS", "Wait for execution reconciliation", true);
                case PENDING_VERIFICATION -> state("VERIFICATION_PENDING", "Verify external state", true);
                case COMPLETED -> state("VERIFIED_COMPLETE", "No action required", false);
                case UNVERIFIED -> state("UNVERIFIED_REVIEW_REQUIRED", "Review and verify external state", true);
                case FAILED -> state("FAILED_REVIEW_REQUIRED", "Review failed execution", true);
            };
        }

        if (action.getStatus() == ProposalStatus.REMEDIATION_AUTHORIZED) {
            return state("AUTHORIZED_EXECUTION_PENDING", "Execute protected remediation", true);
        }
        if (action.getStatus() == ProposalStatus.REMEDIATED) {
            return state("STATE_UNAVAILABLE", "Review incident state", true);
        }
        if (action.getStatus() == ProposalStatus.PENDING) {
            return state("POLICY_EVALUATION_REQUIRED", "Evaluate policy", true);
        }
        if (decision == null) {
            return state("STATE_UNAVAILABLE", "Review incident state", true);
        }
        if (decision.getDecision() == DecisionType.DENY) {
            return state("POLICY_BLOCKED", "Review blocked proposal", true);
        }
        if (PROTECTED_EXECUTION_ACTIONS.contains(action.getAction()) && canRequestHumanAuthorization(action, decision)) {
            return state("HUMAN_APPROVAL_REQUIRED", "Authorize remediation", true);
        }
        if (decision.getDecision() == DecisionType.REDACT) {
            return state("POLICY_REVIEWED", "Review minimized policy result", true);
        }
        return state("POLICY_REVIEWED", "Review policy result", true);
    }

    private boolean canRequestHumanAuthorization(ActionProposalEntity action, PolicyDecisionEntity decision) {
        if (decision.getDecision() == DecisionType.DENY) return false;
        try {
            Set<String> required = REVOKE_CREDENTIAL.equals(action.getAction()) ? REVOKE_REQUIRED_FIELDS : NOTIFY_REQUIRED_FIELDS;
            Set<String> allowed = Set.copyOf(readList(decision.getAllowedFieldsJson()));
            Map<String, String> normalPayload = readMap(action.getNormalPayloadJson());
            if (!allowed.containsAll(required) || !normalPayload.keySet().containsAll(required)) return false;
            if (action.getHost() == null || action.getHost().isBlank()) return false;

            List<String> privateRefs = readList(action.getPrivateRefsJson());
            if (REVOKE_CREDENTIAL.equals(action.getAction())) {
                return "incident-remediation".equals(action.getPurpose()) && privateRefs.isEmpty();
            }
            List<String> allowedPrivateRefs = readList(decision.getAllowedPrivateRefsJson());
            return "incident-notification".equals(action.getPurpose())
                && privateRefs.size() == 1
                && "verified_email".equals(privateRefs.get(0))
                && allowedPrivateRefs.contains("verified_email");
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private List<String> readList(String json) {
        try { return mapper.readValue(json, new TypeReference<List<String>>() {}); }
        catch (Exception ex) { throw new IllegalStateException("Stored workspace metadata is invalid", ex); }
    }

    private Map<String, String> readMap(String json) {
        try { return mapper.readValue(json, new TypeReference<Map<String, String>>() {}); }
        catch (Exception ex) { throw new IllegalStateException("Stored workspace normal payload is invalid", ex); }
    }

    private static OperationalState state(String stage, String nextAction, boolean requiresAttention) {
        return new OperationalState(stage, nextAction, requiresAttention);
    }

    private record OperationalState(String stage, String nextAction, boolean requiresAttention) {}
}
