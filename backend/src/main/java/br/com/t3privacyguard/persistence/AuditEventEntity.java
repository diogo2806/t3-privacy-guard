package br.com.t3privacyguard.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
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
    @Column(name = "t3n_sequence")
    private Long t3nSequence;
    @Column(name = "t3n_hash", length = 128)
    private String t3nHash;
    @Column(name = "t3n_function", length = 120)
    private String t3nFunction;
    @Column(name = "sequence_number")
    private Long sequence;
    @Column(name = "previous_mac", length = 64)
    private String previousMac;
    @Column(name = "event_mac", length = 64)
    private String eventMac;
    @Column(name = "integrity_version", length = 16)
    private String integrityVersion;
    @Column(name = "integrity_key_id", length = 32)
    private String integrityKeyId;

    protected AuditEventEntity() {}

    public AuditEventEntity(String id, String incidentId, String type, String message, Instant createdAt) {
        this(id, incidentId, type, message, createdAt, null, null, null, null, null, null, null, null);
    }

    public AuditEventEntity(
        String id,
        String incidentId,
        String type,
        String message,
        Instant createdAt,
        Long t3nSequence,
        String t3nHash,
        String t3nFunction
    ) {
        this(id, incidentId, type, message, createdAt, t3nSequence, t3nHash, t3nFunction, null, null, null, null, null);
    }

    public AuditEventEntity(
        String id,
        String incidentId,
        String type,
        String message,
        Instant createdAt,
        Long t3nSequence,
        String t3nHash,
        String t3nFunction,
        Long sequence,
        String previousMac,
        String eventMac,
        String integrityVersion,
        String integrityKeyId
    ) {
        this.id = id;
        this.incidentId = incidentId;
        this.type = type;
        this.message = message;
        this.createdAt = createdAt;
        this.t3nSequence = t3nSequence;
        this.t3nHash = t3nHash;
        this.t3nFunction = t3nFunction;
        this.sequence = sequence;
        this.previousMac = previousMac;
        this.eventMac = eventMac;
        this.integrityVersion = integrityVersion;
        this.integrityKeyId = integrityKeyId;
    }

    public String getId() { return id; }
    public String getIncidentId() { return incidentId; }
    public String getType() { return type; }
    public String getMessage() { return message; }
    public Instant getCreatedAt() { return createdAt; }
    public Long getT3nSequence() { return t3nSequence; }
    public String getT3nHash() { return t3nHash; }
    public String getT3nFunction() { return t3nFunction; }
    public Long getSequence() { return sequence; }
    public String getPreviousMac() { return previousMac; }
    public String getEventMac() { return eventMac; }
    public String getIntegrityVersion() { return integrityVersion; }
    public String getIntegrityKeyId() { return integrityKeyId; }
}
