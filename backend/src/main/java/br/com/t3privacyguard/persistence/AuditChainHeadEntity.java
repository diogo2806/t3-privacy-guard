package br.com.t3privacyguard.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "audit_chain_heads")
public class AuditChainHeadEntity {
    @Id
    @Column(name = "incident_id", length = 36)
    private String incidentId;

    @Column(name = "last_sequence", nullable = false)
    private long lastSequence;

    @Column(name = "last_mac", nullable = false, length = 64)
    private String lastMac;

    @Column(name = "integrity_version", nullable = false, length = 16)
    private String integrityVersion;

    protected AuditChainHeadEntity() {}

    public AuditChainHeadEntity(String incidentId, long lastSequence, String lastMac, String integrityVersion) {
        this.incidentId = incidentId;
        this.lastSequence = lastSequence;
        this.lastMac = lastMac;
        this.integrityVersion = integrityVersion;
    }

    public String getIncidentId() { return incidentId; }
    public long getLastSequence() { return lastSequence; }
    public String getLastMac() { return lastMac; }
    public String getIntegrityVersion() { return integrityVersion; }

    public void advance(long sequence, String mac, String version) {
        this.lastSequence = sequence;
        this.lastMac = mac;
        this.integrityVersion = version;
    }
}
