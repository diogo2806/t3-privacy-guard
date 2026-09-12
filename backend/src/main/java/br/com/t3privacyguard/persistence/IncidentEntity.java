package br.com.t3privacyguard.persistence;

import br.com.t3privacyguard.domain.Severity;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "incidents")
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

    protected IncidentEntity() {}

    public IncidentEntity(String id, String title, Severity severity, String summary, String source, Instant createdAt) {
        this.id = id;
        this.title = title;
        this.severity = severity;
        this.summary = summary;
        this.source = source;
        this.status = "OPEN";
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public String getTitle() { return title; }
    public Severity getSeverity() { return severity; }
    public String getSummary() { return summary; }
    public String getSource() { return source; }
    public String getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
}
