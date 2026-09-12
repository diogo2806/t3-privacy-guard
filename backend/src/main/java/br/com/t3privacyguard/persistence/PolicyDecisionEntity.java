package br.com.t3privacyguard.persistence;

import br.com.t3privacyguard.domain.DecisionType;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "policy_decisions", uniqueConstraints = @UniqueConstraint(name = "uk_decision_action", columnNames = "action_proposal_id"))
public class PolicyDecisionEntity {
    @Id
    private String id;
    @Column(name = "action_proposal_id", nullable = false, length = 36)
    private String actionProposalId;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 12)
    private DecisionType decision;
    @Column(nullable = false, length = 80)
    private String reasonCode;
    @Column(nullable = false, length = 800)
    private String reason;
    @Column(nullable = false, length = 4000)
    private String allowedFieldsJson;
    @Column(nullable = false, length = 4000)
    private String redactedFieldsJson;
    @Column(nullable = false)
    private Instant evaluatedAt;

    protected PolicyDecisionEntity() {}

    public PolicyDecisionEntity(String id, String actionProposalId, DecisionType decision, String reasonCode, String reason, String allowedFieldsJson, String redactedFieldsJson, Instant evaluatedAt) {
        this.id = id;
        this.actionProposalId = actionProposalId;
        this.decision = decision;
        this.reasonCode = reasonCode;
        this.reason = reason;
        this.allowedFieldsJson = allowedFieldsJson;
        this.redactedFieldsJson = redactedFieldsJson;
        this.evaluatedAt = evaluatedAt;
    }

    public String getId() { return id; }
    public String getActionProposalId() { return actionProposalId; }
    public DecisionType getDecision() { return decision; }
    public String getReasonCode() { return reasonCode; }
    public String getReason() { return reason; }
    public String getAllowedFieldsJson() { return allowedFieldsJson; }
    public String getRedactedFieldsJson() { return redactedFieldsJson; }
    public Instant getEvaluatedAt() { return evaluatedAt; }
}
