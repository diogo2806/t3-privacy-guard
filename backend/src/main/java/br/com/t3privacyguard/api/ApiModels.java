package br.com.t3privacyguard.api;

import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.ProposalStatus;
import br.com.t3privacyguard.domain.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;
import java.util.List;

public final class ApiModels {
    private ApiModels() {}

    public record CreateIncidentRequest(
        @NotBlank @Size(max = 160) String title,
        @NotNull Severity severity,
        @NotBlank @Size(max = 2000) String summary,
        @NotBlank @Size(max = 120) String source
    ) {}

    public record IncidentResponse(
        String id,
        String title,
        Severity severity,
        String summary,
        String source,
        String status,
        Instant createdAt
    ) {}

    public record CreateActionRequest(
        @NotBlank @Size(max = 128) String requestId,
        @NotBlank @Size(max = 80) String action,
        @NotBlank @Size(max = 240) String resource,
        @NotBlank @Size(max = 80) String purpose,
        @Size(max = 253) String host,
        @NotNull @Size(max = 64) List<@NotBlank @Size(max = 80) String> fields,
        @Size(max = 4) List<@NotBlank @Size(max = 64) String> privateRefs
    ) {}

    public record ActionResponse(
        String id,
        String incidentId,
        String requestId,
        String action,
        String resource,
        String purpose,
        String host,
        List<String> fields,
        List<String> privateRefs,
        ProposalStatus status,
        Instant createdAt
    ) {}

    public record DecisionResponse(
        String id,
        String actionProposalId,
        DecisionType decision,
        String reasonCode,
        String reason,
        List<String> allowedFields,
        List<String> redactedFields,
        List<String> allowedPrivateRefs,
        List<String> redactedPrivateRefs,
        String policyVersion,
        String policyHash,
        Boolean requiresHumanAuthorization,
        Instant evaluatedAt
    ) {}

    public record AuditResponse(String id, String incidentId, String type, String message, Instant createdAt) {}
    public record ExecutionTraceResponse(
        String id,
        String incidentId,
        String actionId,
        String traceId,
        String requestId,
        String stage,
        String state,
        String reasonCode,
        Long durationMs,
        Instant createdAt
    ) {}
    public record RemediationAuthorizationResponse(String incidentId, String actionId, String requestId, String state) {}
    public record RemediationExecutionResponse(
        String incidentId,
        String actionId,
        String requestId,
        String state,
        Integer httpCode,
        String operationId,
        int verificationAttempts,
        String failureCode,
        Instant startedAt,
        Instant completedAt
    ) {}
    public record AnalyzeAgentRequest(@NotBlank @Size(max = 4000) String prompt) {}
    public record AgentAnalysisResponse(String provider, String model, IncidentResponse incident, ActionResponse action, DecisionResponse decision) {}
}
