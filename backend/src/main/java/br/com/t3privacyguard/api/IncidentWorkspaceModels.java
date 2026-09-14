package br.com.t3privacyguard.api;

import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.IncidentOriginType;
import br.com.t3privacyguard.domain.ProposalStatus;
import br.com.t3privacyguard.domain.RemediationStatus;
import br.com.t3privacyguard.domain.Severity;
import java.time.Instant;
import java.util.List;

public final class IncidentWorkspaceModels {
    private IncidentWorkspaceModels() {}

    public record IncidentWorkspaceResponse(
        Instant generatedAt,
        long attentionCount,
        List<IncidentWorkspaceItem> incidents
    ) {}

    public record IncidentWorkspaceItem(
        String id,
        String title,
        Severity severity,
        String source,
        IncidentOriginType originType,
        String incidentStatus,
        Instant createdAt,
        String latestActionId,
        String latestAction,
        ProposalStatus latestActionStatus,
        DecisionType policyDecision,
        RemediationStatus remediationState,
        String stage,
        String nextRequiredAction,
        boolean requiresAttention
    ) {}
}
