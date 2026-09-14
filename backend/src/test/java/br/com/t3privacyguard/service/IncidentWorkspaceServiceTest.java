package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.RemediationStatus;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionEntity;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionEntity;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class IncidentWorkspaceServiceTest {
    private final IncidentRepository incidents = mock(IncidentRepository.class);
    private final ActionProposalRepository actions = mock(ActionProposalRepository.class);
    private final PolicyDecisionRepository decisions = mock(PolicyDecisionRepository.class);
    private final RemediationExecutionRepository remediations = mock(RemediationExecutionRepository.class);
    private final IncidentWorkspaceService service = new IncidentWorkspaceService(incidents, actions, decisions, remediations);

    @Test
    void derivesOperationalStagesFromPersistedLatestStateUsingBatchReads() {
        Instant now = Instant.parse("2026-09-14T13:00:00Z");
        IncidentEntity noAction = incident("i-1", "No action", Severity.CRITICAL, now.minusSeconds(60));
        IncidentEntity blocked = incident("i-2", "Blocked", Severity.HIGH, now.minusSeconds(120));
        IncidentEntity approval = incident("i-3", "Approval", Severity.HIGH, now.minusSeconds(180));
        IncidentEntity pendingVerification = incident("i-4", "Pending verify", Severity.MEDIUM, now.minusSeconds(240));
        IncidentEntity completed = incident("i-5", "Complete", Severity.LOW, now.minusSeconds(300));

        ActionProposalEntity blockedAction = evaluatedAction("a-2", "i-2", "revoke-credential", now.minusSeconds(110));
        ActionProposalEntity approvalAction = evaluatedAction("a-3", "i-3", "notify-security", now.minusSeconds(170));
        ActionProposalEntity verifyAction = authorizedAction("a-4", "i-4", now.minusSeconds(230));
        ActionProposalEntity completedAction = authorizedAction("a-5", "i-5", now.minusSeconds(290));

        PolicyDecisionEntity denied = decision("d-2", blockedAction.getId(), DecisionType.DENY, now.minusSeconds(100));
        PolicyDecisionEntity allowed = decision("d-3", approvalAction.getId(), DecisionType.ALLOW, now.minusSeconds(160));
        PolicyDecisionEntity verifyAllowed = decision("d-4", verifyAction.getId(), DecisionType.ALLOW, now.minusSeconds(220));
        PolicyDecisionEntity completedAllowed = decision("d-5", completedAction.getId(), DecisionType.ALLOW, now.minusSeconds(280));

        RemediationExecutionEntity pending = new RemediationExecutionEntity("r-4", verifyAction.getId(), verifyAction.getRequestId(), now.minusSeconds(200));
        pending.markPendingVerification(202, "op-4", now.minusSeconds(190));
        RemediationExecutionEntity done = new RemediationExecutionEntity("r-5", completedAction.getId(), completedAction.getRequestId(), now.minusSeconds(270));
        done.markPendingVerification(202, "op-5", now.minusSeconds(260));
        done.markCompleted(now.minusSeconds(250));

        when(incidents.findByExpiresAtAfterOrderByCreatedAtDesc(any(Instant.class)))
            .thenReturn(List.of(noAction, blocked, approval, pendingVerification, completed));
        when(actions.findByIncidentIdInOrderByCreatedAtAsc(any())).thenReturn(List.of(blockedAction, approvalAction, verifyAction, completedAction));
        when(decisions.findByActionProposalIdIn(any())).thenReturn(List.of(denied, allowed, verifyAllowed, completedAllowed));
        when(remediations.findByActionProposalIdIn(any())).thenReturn(List.of(pending, done));

        var workspace = service.getWorkspace();

        assertThat(workspace.incidents()).extracting(item -> item.stage()).containsExactly(
            "NEEDS_ANALYSIS",
            "POLICY_BLOCKED",
            "HUMAN_APPROVAL_REQUIRED",
            "VERIFICATION_PENDING",
            "VERIFIED_COMPLETE"
        );
        assertThat(workspace.incidents()).extracting(item -> item.nextRequiredAction()).containsExactly(
            "Analyze incident",
            "Review blocked proposal",
            "Authorize remediation",
            "Verify external state",
            "No action required"
        );
        assertThat(workspace.attentionCount()).isEqualTo(4);
        assertThat(workspace.incidents().get(4).requiresAttention()).isFalse();

        verify(incidents).findByExpiresAtAfterOrderByCreatedAtDesc(any(Instant.class));
        verify(actions).findByIncidentIdInOrderByCreatedAtAsc(any());
        verify(decisions).findByActionProposalIdIn(any());
        verify(remediations).findByActionProposalIdIn(any());
    }

    @Test
    void returnsNeutralStateWhenPersistedStateCannotBeProved() {
        Instant now = Instant.parse("2026-09-14T13:00:00Z");
        IncidentEntity incident = incident("i-1", "Inconsistent", Severity.HIGH, now.minusSeconds(60));
        ActionProposalEntity action = evaluatedAction("a-1", "i-1", "revoke-credential", now.minusSeconds(50));

        when(incidents.findByExpiresAtAfterOrderByCreatedAtDesc(any(Instant.class))).thenReturn(List.of(incident));
        when(actions.findByIncidentIdInOrderByCreatedAtAsc(any())).thenReturn(List.of(action));
        when(decisions.findByActionProposalIdIn(any())).thenReturn(List.of());
        when(remediations.findByActionProposalIdIn(any())).thenReturn(List.of());

        var item = service.getWorkspace().incidents().get(0);

        assertThat(item.stage()).isEqualTo("STATE_UNAVAILABLE");
        assertThat(item.nextRequiredAction()).isEqualTo("Review incident state");
        assertThat(item.requiresAttention()).isTrue();
    }

    @Test
    void keepsEvaluationOnlyActionDistinctFromHumanApprovalRequired() {
        Instant now = Instant.parse("2026-09-14T13:00:00Z");
        IncidentEntity incident = incident("i-1", "Isolation", Severity.HIGH, now.minusSeconds(60));
        ActionProposalEntity action = evaluatedAction("a-1", "i-1", "isolate-account", now.minusSeconds(50));
        PolicyDecisionEntity decision = decision("d-1", action.getId(), DecisionType.ALLOW, now.minusSeconds(40));

        when(incidents.findByExpiresAtAfterOrderByCreatedAtDesc(any(Instant.class))).thenReturn(List.of(incident));
        when(actions.findByIncidentIdInOrderByCreatedAtAsc(any())).thenReturn(List.of(action));
        when(decisions.findByActionProposalIdIn(any())).thenReturn(List.of(decision));
        when(remediations.findByActionProposalIdIn(any())).thenReturn(List.of());

        assertThat(service.getWorkspace().incidents().get(0).stage()).isEqualTo("POLICY_REVIEWED");
    }

    @Test
    void returnsEmptyWorkspaceWithoutSecondaryQueries() {
        when(incidents.findByExpiresAtAfterOrderByCreatedAtDesc(any(Instant.class))).thenReturn(List.of());

        var workspace = service.getWorkspace();

        assertThat(workspace.attentionCount()).isZero();
        assertThat(workspace.incidents()).isEmpty();
    }

    private static IncidentEntity incident(String id, String title, Severity severity, Instant createdAt) {
        return new IncidentEntity(id, title, severity, "Synthetic summary", "test", createdAt, createdAt.plusSeconds(3600));
    }

    private static ActionProposalEntity evaluatedAction(String id, String incidentId, String actionName, Instant createdAt) {
        ActionProposalEntity action = new ActionProposalEntity(
            id, incidentId, "request-" + id, actionName, "resource:test", "incident-remediation", "security.example",
            "[\"incident_id\",\"credential_id\",\"reason\"]", "{}", "[]", createdAt
        );
        action.markEvaluated();
        return action;
    }

    private static ActionProposalEntity authorizedAction(String id, String incidentId, Instant createdAt) {
        ActionProposalEntity action = evaluatedAction(id, incidentId, "revoke-credential", createdAt);
        action.authorizeRemediation("approver-01", createdAt.plusSeconds(1));
        return action;
    }

    private static PolicyDecisionEntity decision(String id, String actionId, DecisionType type, Instant evaluatedAt) {
        return new PolicyDecisionEntity(
            id, actionId, type, "TEST", "Synthetic decision", "[]", "[]", "[]", "[]",
            "policy-v1", "a".repeat(64), true, evaluatedAt
        );
    }
}
