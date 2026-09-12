package br.com.t3privacyguard.persistence;

import br.com.t3privacyguard.domain.RemediationStatus;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;
import java.time.Instant;

@Entity
@Table(
    name = "remediation_executions",
    uniqueConstraints = @UniqueConstraint(name = "uk_remediation_action", columnNames = "action_proposal_id")
)
public class RemediationExecutionEntity {
    @Id
    private String id;

    @Column(name = "action_proposal_id", nullable = false, length = 36)
    private String actionProposalId;

    @Column(name = "request_id", nullable = false, length = 128)
    private String requestId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private RemediationStatus status;

    @Column(name = "http_code")
    private Integer httpCode;

    @Column(name = "operation_id", length = 200)
    private String operationId;

    @Column(name = "started_at", nullable = false)
    private Instant startedAt;

    @Column(name = "last_attempt_at", nullable = false)
    private Instant lastAttemptAt;

    @Column(name = "verification_attempts", nullable = false)
    private int verificationAttempts;

    @Column(name = "completed_at")
    private Instant completedAt;

    @Column(name = "failure_code", length = 120)
    private String failureCode;

    @Version
    private long version;

    protected RemediationExecutionEntity() {}

    public RemediationExecutionEntity(String id, String actionProposalId, String requestId, Instant now) {
        this.id = id;
        this.actionProposalId = actionProposalId;
        this.requestId = requestId;
        this.status = RemediationStatus.EXECUTING;
        this.startedAt = now;
        this.lastAttemptAt = now;
        this.verificationAttempts = 0;
    }

    public void markPendingVerification(int httpCode, String operationId, Instant now) {
        this.status = RemediationStatus.PENDING_VERIFICATION;
        this.httpCode = httpCode;
        this.operationId = operationId;
        this.lastAttemptAt = now;
        this.failureCode = null;
    }

    public void markVerificationAttempt(Instant now) {
        this.verificationAttempts += 1;
        this.lastAttemptAt = now;
    }

    public void markCompleted(Instant now) {
        this.status = RemediationStatus.COMPLETED;
        this.completedAt = now;
        this.lastAttemptAt = now;
        this.failureCode = null;
    }

    public void markUnverified(String failureCode, Instant now) {
        this.status = RemediationStatus.UNVERIFIED;
        this.failureCode = failureCode;
        this.lastAttemptAt = now;
    }

    public void markFailed(String failureCode, Instant now) {
        this.status = RemediationStatus.FAILED;
        this.failureCode = failureCode;
        this.lastAttemptAt = now;
    }

    public String getId() { return id; }
    public String getActionProposalId() { return actionProposalId; }
    public String getRequestId() { return requestId; }
    public RemediationStatus getStatus() { return status; }
    public Integer getHttpCode() { return httpCode; }
    public String getOperationId() { return operationId; }
    public Instant getStartedAt() { return startedAt; }
    public Instant getLastAttemptAt() { return lastAttemptAt; }
    public int getVerificationAttempts() { return verificationAttempts; }
    public Instant getCompletedAt() { return completedAt; }
    public String getFailureCode() { return failureCode; }
    public long getVersion() { return version; }
}
