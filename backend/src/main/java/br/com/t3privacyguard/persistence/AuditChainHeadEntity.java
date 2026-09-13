package br.com.t3privacyguard.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "audit_chain_heads")
public class AuditChainHeadEntity {
    @Id
    @Column(name = "incident_id", length = 36)
    private String incidentId;
    @Column(name = "last_sequence", nullable = false)
    private long lastSequence;
    @Column(name = "last_event_mac", nullable = false, length = 64)
    private String lastEventMac;
    @Column(name = "integrity_version", nullable = false, length = 16)
    private String integrityVersion;
    @Column(name = "integrity_key_id", nullable = false, length = 32)
    private String integrityKeyId;
    @Column(name = "legacy_event_count", nullable = false)
    private long legacyEventCount;
    @Column(name = "head_mac", nullable = false, length = 64)
    private String headMac;
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AuditChainHeadEntity() {}

    public AuditChainHeadEntity(
        String incidentId,
        long lastSequence,
        String lastEventMac,
        String integrityVersion,
        String integrityKeyId,
        long legacyEventCount,
        String headMac,
        Instant updatedAt
    ) {
        this.incidentId = incidentId;
        this.lastSequence = lastSequence;
        this.lastEventMac = lastEventMac;
        this.integrityVersion = integrityVersion;
        this.integrityKeyId = integrityKeyId;
        this.legacyEventCount = legacyEventCount;
        this.headMac = headMac;
        this.updatedAt = updatedAt;
    }

    public void advance(
        long sequence,
        String eventMac,
        String version,
        String keyId,
        long legacyCount,
        String newHeadMac,
        Instant now
    ) {
        this.lastSequence = sequence;
        this.lastEventMac = eventMac;
        this.integrityVersion = version;
        this.integrityKeyId = keyId;
        this.legacyEventCount = legacyCount;
        this.headMac = newHeadMac;
        this.updatedAt = now;
    }

    public String getIncidentId() { return incidentId; }
    public long getLastSequence() { return lastSequence; }
    public String getLastEventMac() { return lastEventMac; }
    public String getIntegrityVersion() { return integrityVersion; }
    public String getIntegrityKeyId() { return integrityKeyId; }
    public long getLegacyEventCount() { return legacyEventCount; }
    public String getHeadMac() { return headMac; }
    public Instant getUpdatedAt() { return updatedAt; }
}
