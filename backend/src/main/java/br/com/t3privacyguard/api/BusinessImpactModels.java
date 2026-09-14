package br.com.t3privacyguard.api;

import java.time.Instant;

public final class BusinessImpactModels {
    private BusinessImpactModels() {}

    public record BusinessImpactResponse(
        String window,
        Instant from,
        Instant to,
        boolean retentionLimited,
        long evaluatedActions,
        long deniedBeforeEgress,
        long minimizedDecisions,
        long redactedNormalFieldNames,
        long redactedPrivateRefs,
        long humanAuthorizedRemediations,
        long verifiedCompleted,
        long unverified,
        long failed,
        long finalizedExecutions,
        Double blockedRatePct,
        Double verifiedCompletionRatePct,
        Long medianDecisionMs,
        Long medianVerifiedOutcomeMs
    ) {}
}
