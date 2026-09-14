package br.com.t3privacyguard.persistence;

import br.com.t3privacyguard.domain.IncidentOriginType;
import br.com.t3privacyguard.domain.Severity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;

@Entity
@Table(
    name = "incidents",
    uniqueConstraints = @UniqueConstraint(
        name = "uk_incident_integration_external_event",
        columnNames = {"integration_id", "external_event_id"}
    )
)
public class IncidentEntity {
    @Id
    private String id;

    @Column(nullable = false, length = 160)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Severity severity;

    @Column(nullable = false, length = 2000)
    private String summary;

    @Column(nullable = false, length = 120)
    private String source;

    @Column(nullable = false, length = 32)
    private String status;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "origin_type", length = 24)
    private IncidentOriginType originType;

    @Column(name = "integration_id", length = 64)
    private String integrationId;

    @Column(name = "external_event_id", length = 128)
    private String externalEventId;

    protected IncidentEntity() {}

    public IncidentEntity(String id, String title, Severity severity, String summary, String source, Instant createdAt, Instant expiresAt) {
        this(id, title, severity, summary, source, createdAt, expiresAt, IncidentOriginType.APPLICATION, null, null);
    }

    public IncidentEntity(
        String id,
        String title,
        Severity severity,
        String summary,
        String source,
        Instant createdAt,
        Instant expiresAt,
        IncidentOriginType originType,
        String integrationId,
        String externalEventId
    ) {
        this.id = id;
        this.title = title;
        this.severity = severity;
        this.summary = summary;
        this.source = source;
        this.status = "OPEN";
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.originType = originType;
        this.integrationId = integrationId;
        this.externalEventId = externalEventId;
    }

    @PrePersist
    void validateRetentionMetadata() {
        if (expiresAt == null) throw new IllegalStateException("Incident retention metadata is required");
        validateProvenance();
    }

    public void assignExpiresAtIfMissing(Instant expiresAt) {
        if (this.expiresAt == null) this.expiresAt = expiresAt;
    }

    public void assignExternalProvenance(String integrationId, String externalEventId) {
        if (integrationId == null || integrationId.isBlank() || externalEventId == null || externalEventId.isBlank()) {
            throw new IllegalArgumentException("External incident provenance is required");
        }
        if (this.integrationId != null || this.externalEventId != null || effectiveOriginType() == IncidentOriginType.EXTERNAL) {
            throw new IllegalStateException("Incident origin has already been assigned");
        }
        this.originType = IncidentOriginType.EXTERNAL;
        this.integrationId = integrationId;
        this.externalEventId = externalEventId;
        validateProvenance();
    }

    public String getId() { return id; }
    public String getTitle() { return title; }
    public Severity getSeverity() { return severity; }
    public String getSummary() { return summary; }
    public String getSource() { return source; }
    public String getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public IncidentOriginType getOriginType() { return effectiveOriginType(); }
    public String getIntegrationId() { return integrationId; }
    public String getExternalEventId() { return externalEventId; }

    private void validateProvenance() {
        if (effectiveOriginType() == IncidentOriginType.EXTERNAL) {
            if (integrationId == null || integrationId.isBlank() || externalEventId == null || externalEventId.isBlank()) {
                throw new IllegalStateException("External incident provenance is required");
            }
        } else if (integrationId != null || externalEventId != null) {
            throw new IllegalStateException("Application incident cannot carry external integration provenance");
        }
    }

    private IncidentOriginType effectiveOriginType() {
        return originType == null ? IncidentOriginType.APPLICATION : originType;
    }
}
