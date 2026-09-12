package br.com.t3privacyguard.persistence;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_events")
public class AuditEventEntity {
    @Id
    private String id;
    @Column(name = "incident_id", nullable = false, length = 36)
    private String incidentId;
    @Column(nullable = false, length = 64)
    private String type;
    @Column(nullable = false, length = 600)
    private String message;
    @Column(nullable = false)
    private Instant createdAt;

    protected AuditEventEntity() {}

    public AuditEventEntity(String id, String incidentId, String type, String message, Instant createdAt) {
        this.id = id;
        this.incidentId = incidentId;
        this.type = type;
        this.message = message;
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public String getIncidentId() { return incidentId; }
    public String getType() { return type; }
    public String getMessage() { return message; }
    public Instant getCreatedAt() { return createdAt; }
}
