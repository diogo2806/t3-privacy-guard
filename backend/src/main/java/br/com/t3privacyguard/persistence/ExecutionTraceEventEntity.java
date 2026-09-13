package br.com.t3privacyguard.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(
    name = "execution_trace_events",
    indexes = @Index(name = "idx_trace_incident_action_time", columnList = "incident_id,action_id,created_at")
)
public class ExecutionTraceEventEntity {
    @Id
    @Column(length = 36)
    private String id;
    @Column(name = "incident_id", nullable = false, length = 36)
    private String incidentId;
    @Column(name = "action_id", nullable = false, length = 36)
    private String actionId;
    @Column(name = "request_id", nullable = false, length = 128)
    private String requestId;
    @Column(name = "trace_id", nullable = false, length = 64)
    private String traceId;
    @Column(nullable = false, length = 64)
    private String stage;
    @Column(nullable = false, length = 32)
    private String state;
    @Column(name = "reason_code", length = 80)
    private String reasonCode;
    @Column(name = "duration_ms")
    private Long durationMs;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected ExecutionTraceEventEntity() {}

    public ExecutionTraceEventEntity(
        String id,
        String incidentId,
        String actionId,
        String requestId,
        String traceId,
        String stage,
        String state,
        String reasonCode,
        Long durationMs,
        Instant createdAt
    ) {
        this.id = id;
        this.incidentId = incidentId;
        this.actionId = actionId;
        this.requestId = requestId;
        this.traceId = traceId;
        this.stage = stage;
        this.state = state;
        this.reasonCode = reasonCode;
        this.durationMs = durationMs;
        this.createdAt = createdAt;
    }

    public String getId() { return id; }
    public String getIncidentId() { return incidentId; }
    public String getActionId() { return actionId; }
    public String getRequestId() { return requestId; }
    public String getTraceId() { return traceId; }
    public String getStage() { return stage; }
    public String getState() { return state; }
    public String getReasonCode() { return reasonCode; }
    public Long getDurationMs() { return durationMs; }
    public Instant getCreatedAt() { return createdAt; }
}
