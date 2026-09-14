package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionEntity;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import br.com.t3privacyguard.privacy.IncidentRetentionProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class BusinessImpactServiceTest {
    private PolicyDecisionRepository decisions;
    private ActionProposalRepository actions;
    private RemediationExecutionRepository executions;
    private IncidentRetentionProperties retention;
    private BusinessImpactService service;

    @BeforeEach
    void setUp() {
        decisions = mock(PolicyDecisionRepository.class);
        actions = mock(ActionProposalRepository.class);
        executions = mock(RemediationExecutionRepository.class);
        retention = new IncidentRetentionProperties();
        retention.setDays(7);
        service = new BusinessImpactService(decisions, actions, executions, retention, new ObjectMapper());
    }

    @Test
    void calculatesOnlyObservedOperationalImpactWithExplicitDenominators() {
        Instant now = Instant.parse("2026-09-14T12:00:00Z");
        Instant decisionOneAt = now.minus(Duration.ofMinutes(10));
        Instant decisionTwoAt = now.minus(Duration.ofMinutes(9));

        ActionProposalEntity actionOne = action("action-1", decisionOneAt.minusMillis(100));
        ActionProposalEntity actionTwo = action("action-2", decisionTwoAt.minusMillis(300));
        PolicyDecisionEntity denied = decision("decision-1", "action-1", DecisionType.DENY, decisionOneAt, "[]", "[]");
        PolicyDecisionEntity redacted = decision(
            "decision-2",
            "action-2",
            DecisionType.REDACT,
            decisionTwoAt,
            "[\"employee_department\",\"debug_note\"]",
            "[\"verified_email\"]"
        );

        RemediationExecutionEntity completedOne = execution("execution-1", "action-1", decisionOneAt.minusMillis(900));
        completedOne.markCompleted(actionOne.getCreatedAt().plusMillis(1000));
        RemediationExecutionEntity completedTwo = execution("execution-2", "action-2", decisionTwoAt.minusMillis(2700));
        completedTwo.markCompleted(actionTwo.getCreatedAt().plusMillis(3000));
        RemediationExecutionEntity unverified = execution("execution-3", "action-3", now.minusSeconds(120));
        unverified.markUnverified("VERIFICATION_UNAVAILABLE", now.minusSeconds(60));
        RemediationExecutionEntity failed = execution("execution-4", "action-4", now.minusSeconds(120));
        failed.markFailed("EXECUTION_DESTINATION_CHANGED", now.minusSeconds(30));

        when(decisions.findByEvaluatedAtBetweenOrderByEvaluatedAtAsc(any(Instant.class), any(Instant.class)))
            .thenReturn(List.of(denied, redacted));
        when(executions.findByLastAttemptAtBetweenOrderByLastAttemptAtAsc(any(Instant.class), any(Instant.class)))
            .thenReturn(List.of(completedOne, completedTwo, unverified, failed));
        when(actions.countByRemediationAuthorizedAtBetween(any(Instant.class), any(Instant.class))).thenReturn(3L);
        when(actions.findAllById(any())).thenReturn(List.of(actionOne, actionTwo));

        var impact = service.getImpact(BusinessImpactService.Window.RETAINED, now);

        assertThat(impact.window()).isEqualTo("RETAINED");
        assertThat(impact.from()).isEqualTo(now.minus(Duration.ofDays(7)));
        assertThat(impact.to()).isEqualTo(now);
        assertThat(impact.retentionLimited()).isFalse();
        assertThat(impact.evaluatedActions()).isEqualTo(2);
        assertThat(impact.deniedBeforeEgress()).isEqualTo(1);
        assertThat(impact.minimizedDecisions()).isEqualTo(1);
        assertThat(impact.redactedNormalFieldNames()).isEqualTo(2);
        assertThat(impact.redactedPrivateRefs()).isEqualTo(1);
        assertThat(impact.humanAuthorizedRemediations()).isEqualTo(3);
        assertThat(impact.verifiedCompleted()).isEqualTo(2);
        assertThat(impact.unverified()).isEqualTo(1);
        assertThat(impact.failed()).isEqualTo(1);
        assertThat(impact.finalizedExecutions()).isEqualTo(4);
        assertThat(impact.blockedRatePct()).isEqualTo(50.0d);
        assertThat(impact.verifiedCompletionRatePct()).isEqualTo(50.0d);
        assertThat(impact.medianDecisionMs()).isEqualTo(200L);
        assertThat(impact.medianVerifiedOutcomeMs()).isEqualTo(2000L);
    }

    @Test
    void returnsNotObservedRatesAndLatenciesWhenThereIsNoDenominator() {
        Instant now = Instant.parse("2026-09-14T12:00:00Z");
        when(decisions.findByEvaluatedAtBetweenOrderByEvaluatedAtAsc(any(Instant.class), any(Instant.class))).thenReturn(List.of());
        when(executions.findByLastAttemptAtBetweenOrderByLastAttemptAtAsc(any(Instant.class), any(Instant.class))).thenReturn(List.of());
        when(actions.countByRemediationAuthorizedAtBetween(any(Instant.class), any(Instant.class))).thenReturn(0L);
        when(actions.findAllById(any())).thenReturn(List.of());

        var impact = service.getImpact(BusinessImpactService.Window.HOURS_24, now);

        assertThat(impact.evaluatedActions()).isZero();
        assertThat(impact.finalizedExecutions()).isZero();
        assertThat(impact.blockedRatePct()).isNull();
        assertThat(impact.verifiedCompletionRatePct()).isNull();
        assertThat(impact.medianDecisionMs()).isNull();
        assertThat(impact.medianVerifiedOutcomeMs()).isNull();
    }

    @Test
    void limitsRequestedWindowToConfiguredRetention() {
        Instant now = Instant.parse("2026-09-14T12:00:00Z");
        retention.setDays(3);
        when(decisions.findByEvaluatedAtBetweenOrderByEvaluatedAtAsc(any(Instant.class), any(Instant.class))).thenReturn(List.of());
        when(executions.findByLastAttemptAtBetweenOrderByLastAttemptAtAsc(any(Instant.class), any(Instant.class))).thenReturn(List.of());
        when(actions.countByRemediationAuthorizedAtBetween(any(Instant.class), any(Instant.class))).thenReturn(0L);
        when(actions.findAllById(any())).thenReturn(List.of());

        var impact = service.getImpact(BusinessImpactService.Window.DAYS_7, now);

        assertThat(impact.window()).isEqualTo("7D");
        assertThat(impact.from()).isEqualTo(now.minus(Duration.ofDays(3)));
        assertThat(impact.retentionLimited()).isTrue();
    }

    @Test
    void ignoresNegativeLatencyInsteadOfReportingAnImpossibleDuration() {
        Instant now = Instant.parse("2026-09-14T12:00:00Z");
        PolicyDecisionEntity decision = decision("decision-1", "action-1", DecisionType.ALLOW, now.minusSeconds(10), "[]", "[]");
        ActionProposalEntity action = action("action-1", now);
        when(decisions.findByEvaluatedAtBetweenOrderByEvaluatedAtAsc(any(Instant.class), any(Instant.class))).thenReturn(List.of(decision));
        when(executions.findByLastAttemptAtBetweenOrderByLastAttemptAtAsc(any(Instant.class), any(Instant.class))).thenReturn(List.of());
        when(actions.countByRemediationAuthorizedAtBetween(any(Instant.class), any(Instant.class))).thenReturn(0L);
        when(actions.findAllById(any())).thenReturn(List.of(action));

        var impact = service.getImpact(BusinessImpactService.Window.RETAINED, now);

        assertThat(impact.medianDecisionMs()).isNull();
    }

    @Test
    void failsInsteadOfInventingAFieldCountWhenStoredPolicyJsonIsCorrupt() {
        Instant now = Instant.parse("2026-09-14T12:00:00Z");
        PolicyDecisionEntity corrupt = decision("decision-1", "action-1", DecisionType.REDACT, now.minusSeconds(10), "not-json", "[]");
        when(decisions.findByEvaluatedAtBetweenOrderByEvaluatedAtAsc(any(Instant.class), any(Instant.class))).thenReturn(List.of(corrupt));
        when(executions.findByLastAttemptAtBetweenOrderByLastAttemptAtAsc(any(Instant.class), any(Instant.class))).thenReturn(List.of());
        when(actions.countByRemediationAuthorizedAtBetween(any(Instant.class), any(Instant.class))).thenReturn(0L);

        assertThatThrownBy(() -> service.getImpact(BusinessImpactService.Window.RETAINED, now))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("policy minimization metadata");
    }

    @Test
    void rejectsUnsupportedWindows() {
        assertThatThrownBy(() -> service.getImpact("30d"))
            .isInstanceOf(InvalidBusinessImpactWindowException.class)
            .hasMessageContaining("retained, 24h or 7d");
    }

    private static ActionProposalEntity action(String id, Instant createdAt) {
        return new ActionProposalEntity(
            id,
            "incident-1",
            "request-" + id,
            "revoke-credential",
            "credential:test",
            "incident-remediation",
            "security.example",
            "[\"incident_id\",\"credential_id\",\"reason\"]",
            "{\"incident_id\":\"inc-1\",\"credential_id\":\"cred-1\",\"reason\":\"synthetic\"}",
            "[]",
            createdAt
        );
    }

    private static PolicyDecisionEntity decision(
        String id,
        String actionId,
        DecisionType type,
        Instant evaluatedAt,
        String redactedFields,
        String redactedPrivateRefs
    ) {
        return new PolicyDecisionEntity(
            id,
            actionId,
            type,
            "TEST",
            "Synthetic test decision",
            "[]",
            redactedFields,
            "[]",
            redactedPrivateRefs,
            "policy-v1",
            "a".repeat(64),
            true,
            evaluatedAt
        );
    }

    private static RemediationExecutionEntity execution(String id, String actionId, Instant startedAt) {
        return new RemediationExecutionEntity(id, actionId, "request-" + actionId, startedAt);
    }
}
