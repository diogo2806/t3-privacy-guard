package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.BusinessImpactModels.BusinessImpactResponse;
import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.RemediationStatus;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionEntity;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import br.com.t3privacyguard.privacy.IncidentRetentionProperties;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class BusinessImpactService {
    private final PolicyDecisionRepository decisions;
    private final ActionProposalRepository actions;
    private final RemediationExecutionRepository executions;
    private final IncidentRetentionProperties retentionProperties;
    private final ObjectMapper mapper;

    public BusinessImpactService(
        PolicyDecisionRepository decisions,
        ActionProposalRepository actions,
        RemediationExecutionRepository executions,
        IncidentRetentionProperties retentionProperties,
        ObjectMapper mapper
    ) {
        this.decisions = decisions;
        this.actions = actions;
        this.executions = executions;
        this.retentionProperties = retentionProperties;
        this.mapper = mapper;
    }

    @Transactional(readOnly = true)
    public BusinessImpactResponse getImpact(String requestedWindow) {
        return getImpact(Window.parse(requestedWindow), Instant.now());
    }

    BusinessImpactResponse getImpact(Window window, Instant now) {
        Coverage coverage = coverage(window, now);
        List<PolicyDecisionEntity> observedDecisions = decisions.findByEvaluatedAtBetweenOrderByEvaluatedAtAsc(coverage.from(), coverage.to());
        List<RemediationExecutionEntity> observedExecutions = executions.findByLastAttemptAtBetweenOrderByLastAttemptAtAsc(coverage.from(), coverage.to());
        long humanAuthorized = actions.countByRemediationAuthorizedAtBetween(coverage.from(), coverage.to());

        long evaluated = observedDecisions.size();
        long denied = observedDecisions.stream().filter(item -> item.getDecision() == DecisionType.DENY).count();
        long minimized = observedDecisions.stream().filter(item -> item.getDecision() == DecisionType.REDACT).count();
        long redactedFields = observedDecisions.stream().mapToLong(item -> listSize(item.getRedactedFieldsJson())).sum();
        long redactedPrivateRefs = observedDecisions.stream().mapToLong(item -> listSize(item.getRedactedPrivateRefsJson())).sum();

        long completed = observedExecutions.stream().filter(item -> item.getStatus() == RemediationStatus.COMPLETED).count();
        long unverified = observedExecutions.stream().filter(item -> item.getStatus() == RemediationStatus.UNVERIFIED).count();
        long failed = observedExecutions.stream().filter(item -> item.getStatus() == RemediationStatus.FAILED).count();
        long finalized = completed + unverified + failed;

        Set<String> actionIds = new LinkedHashSet<>();
        observedDecisions.forEach(item -> actionIds.add(item.getActionProposalId()));
        observedExecutions.stream()
            .filter(item -> item.getStatus() == RemediationStatus.COMPLETED)
            .forEach(item -> actionIds.add(item.getActionProposalId()));
        Map<String, ActionProposalEntity> actionById = actions.findAllById(actionIds).stream()
            .collect(Collectors.toMap(ActionProposalEntity::getId, Function.identity()));

        List<Long> decisionLatencies = new ArrayList<>();
        for (PolicyDecisionEntity decision : observedDecisions) {
            ActionProposalEntity action = actionById.get(decision.getActionProposalId());
            addNonNegativeLatency(decisionLatencies, action == null ? null : action.getCreatedAt(), decision.getEvaluatedAt());
        }

        List<Long> verifiedOutcomeLatencies = new ArrayList<>();
        for (RemediationExecutionEntity execution : observedExecutions) {
            if (execution.getStatus() != RemediationStatus.COMPLETED || execution.getCompletedAt() == null) continue;
            ActionProposalEntity action = actionById.get(execution.getActionProposalId());
            addNonNegativeLatency(verifiedOutcomeLatencies, action == null ? null : action.getCreatedAt(), execution.getCompletedAt());
        }

        return new BusinessImpactResponse(
            window.apiValue,
            coverage.from(),
            coverage.to(),
            coverage.retentionLimited(),
            evaluated,
            denied,
            minimized,
            redactedFields,
            redactedPrivateRefs,
            humanAuthorized,
            completed,
            unverified,
            failed,
            finalized,
            percentage(denied, evaluated),
            percentage(completed, finalized),
            median(decisionLatencies),
            median(verifiedOutcomeLatencies)
        );
    }

    private Coverage coverage(Window window, Instant now) {
        Instant retentionFloor = now.minus(retentionProperties.retention());
        Instant requestedFrom = switch (window) {
            case RETAINED -> retentionFloor;
            case HOURS_24 -> now.minus(Duration.ofHours(24));
            case DAYS_7 -> now.minus(Duration.ofDays(7));
        };
        boolean retentionLimited = window != Window.RETAINED && retentionFloor.isAfter(requestedFrom);
        Instant effectiveFrom = retentionFloor.isAfter(requestedFrom) ? retentionFloor : requestedFrom;
        return new Coverage(effectiveFrom, now, retentionLimited);
    }

    private long listSize(String json) {
        try {
            List<String> values = mapper.readValue(json, new TypeReference<List<String>>() {});
            return values.size();
        } catch (JsonProcessingException | RuntimeException exception) {
            throw new IllegalStateException("Stored policy minimization metadata is invalid", exception);
        }
    }

    private static void addNonNegativeLatency(List<Long> target, Instant start, Instant end) {
        if (start == null || end == null || end.isBefore(start)) return;
        target.add(Duration.between(start, end).toMillis());
    }

    private static Double percentage(long numerator, long denominator) {
        if (denominator == 0) return null;
        return Math.round(((double) numerator / (double) denominator) * 1000.0d) / 10.0d;
    }

    private static Long median(List<Long> values) {
        if (values.isEmpty()) return null;
        values.sort(Comparator.naturalOrder());
        int middle = values.size() / 2;
        if (values.size() % 2 == 1) return values.get(middle);
        return Math.round((values.get(middle - 1) + values.get(middle)) / 2.0d);
    }

    enum Window {
        RETAINED("RETAINED"),
        HOURS_24("24H"),
        DAYS_7("7D");

        private final String apiValue;

        Window(String apiValue) {
            this.apiValue = apiValue;
        }

        static Window parse(String raw) {
            String value = raw == null ? "retained" : raw.trim().toLowerCase(Locale.ROOT);
            return switch (value) {
                case "retained" -> RETAINED;
                case "24h" -> HOURS_24;
                case "7d" -> DAYS_7;
                default -> throw new InvalidBusinessImpactWindowException("window must be one of retained, 24h or 7d");
            };
        }
    }

    private record Coverage(Instant from, Instant to, boolean retentionLimited) {}
}
