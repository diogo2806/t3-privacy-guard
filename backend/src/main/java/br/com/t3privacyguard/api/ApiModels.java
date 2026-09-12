package br.com.t3privacyguard.api;

import br.com.t3privacyguard.domain.*;
import jakarta.validation.constraints.*;
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

    public record IncidentResponse(String id, String title, Severity severity, String summary, String source, String status, Instant createdAt) {}

    public record CreateActionRequest(
        @NotBlank @Size(max = 128) String requestId,
        @NotBlank @Size(max = 80) String action,
        @NotBlank @Size(max = 240) String resource,
        @NotBlank @Size(max = 80) String purpose,
        @Size(max = 253) String host,
        @NotNull @Size(max = 64) List<@NotBlank @Size(max = 80) String> fields
    ) {}

    public record ActionResponse(String id, String incidentId, String requestId, String action, String resource, String purpose, String host, List<String> fields, ProposalStatus status, Instant createdAt) {}

    public record DecisionResponse(String id, String actionProposalId, DecisionType decision, String reasonCode, String reason, List<String> allowedFields, List<String> redactedFields, Instant evaluatedAt) {}

    public record AuditResponse(String id, String incidentId, String type, String message, Instant createdAt) {}

    public record RemediationAuthorizationResponse(String incidentId, String actionId, String requestId, String state) {}
}
