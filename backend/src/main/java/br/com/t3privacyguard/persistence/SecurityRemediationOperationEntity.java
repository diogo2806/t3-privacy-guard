package br.com.t3privacyguard.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;

@Entity
@Table(
    name = "security_remediation_operations",
    uniqueConstraints = @UniqueConstraint(name = "uk_security_remediation_request", columnNames = "request_id")
)
public class SecurityRemediationOperationEntity {
    @Id
    @Column(name = "operation_id", length = 80)
    private String operationId;

    @Column(name = "request_id", nullable = false, length = 128)
    private String requestId;

    @Column(nullable = false, length = 32)
    private String action;

    @Column(nullable = false, length = 32)
    private String state;

    @Column(name = "recipient_resolved", nullable = false)
    private boolean recipientResolved;

    @Column(name = "must_egress_seen", nullable = false)
    private boolean mustEgressSeen;

    @Column(name = "must_not_egress_seen", nullable = false)
    private boolean mustNotEgressSeen;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected SecurityRemediationOperationEntity() {}

    public SecurityRemediationOperationEntity(
        String operationId,
        String requestId,
        String action,
        String state,
        boolean recipientResolved,
        boolean mustEgressSeen,
        boolean mustNotEgressSeen,
        Instant now
    ) {
        this.operationId = operationId;
        this.requestId = requestId;
        this.action = action;
        this.state = state;
        this.recipientResolved = recipientResolved;
        this.mustEgressSeen = mustEgressSeen;
        this.mustNotEgressSeen = mustNotEgressSeen;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public String getOperationId() { return operationId; }
    public String getRequestId() { return requestId; }
    public String getAction() { return action; }
    public String getState() { return state; }
    public boolean isRecipientResolved() { return recipientResolved; }
    public boolean isMustEgressSeen() { return mustEgressSeen; }
    public boolean isMustNotEgressSeen() { return mustNotEgressSeen; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
