package br.com.t3privacyguard.persistence;

import br.com.t3privacyguard.domain.ProposalStatus;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "action_proposals", uniqueConstraints = @UniqueConstraint(name = "uk_action_request_id", columnNames = "request_id"))
public class ActionProposalEntity {
    @Id
    private String id;
    @Column(name = "incident_id", nullable = false, length = 36)
    private String incidentId;
    @Column(name = "request_id", nullable = false, length = 128)
    private String requestId;
    @Column(nullable = false, length = 80)
    private String action;
    @Column(nullable = false, length = 240)
    private String resource;
    @Column(nullable = false, length = 80)
    private String purpose;
    @Column(length = 253)
    private String host;
    @Column(name = "fields_json", nullable = false, length = 4000)
    private String fieldsJson;
    @Column(name = "normal_payload_json", length = 8000)
    private String normalPayloadJson;
    @Column(name = "private_refs_json", nullable = false, length = 1000)
    private String privateRefsJson;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 40)
    private ProposalStatus status;
    @Column(nullable = false)
    private Instant createdAt;
    @Column(name = "remediation_authorized_by", length = 120)
    private String remediationAuthorizedBy;
    @Column(name = "remediation_authorized_at")
    private Instant remediationAuthorizedAt;

    protected ActionProposalEntity() {}

    public ActionProposalEntity(
        String id, String incidentId, String requestId, String action, String resource, String purpose,
        String host, String fieldsJson, String normalPayloadJson, String privateRefsJson, Instant createdAt
    ) {
        this.id = id;
        this.incidentId = incidentId;
        this.requestId = requestId;
        this.action = action;
        this.resource = resource;
        this.purpose = purpose;
        this.host = host;
        this.fieldsJson = fieldsJson;
        this.normalPayloadJson = normalPayloadJson;
        this.privateRefsJson = privateRefsJson;
        this.status = ProposalStatus.PENDING;
        this.createdAt = createdAt;
    }

    public ActionProposalEntity(
        String id, String incidentId, String requestId, String action, String resource, String purpose,
        String host, String fieldsJson, String privateRefsJson, Instant createdAt
    ) {
        this(id, incidentId, requestId, action, resource, purpose, host, fieldsJson, null, privateRefsJson, createdAt);
    }

    public void markEvaluated() { this.status = ProposalStatus.EVALUATED; }
    public void authorizeRemediation(String authorizedBy, Instant authorizedAt) {
        this.status = ProposalStatus.REMEDIATION_AUTHORIZED;
        this.remediationAuthorizedBy = authorizedBy;
        this.remediationAuthorizedAt = authorizedAt;
    }
    public void markRemediated() { this.status = ProposalStatus.REMEDIATED; }
    public String getId() { return id; }
    public String getIncidentId() { return incidentId; }
    public String getRequestId() { return requestId; }
    public String getAction() { return action; }
    public String getResource() { return resource; }
    public String getPurpose() { return purpose; }
    public String getHost() { return host; }
    public String getFieldsJson() { return fieldsJson; }
    public String getNormalPayloadJson() { return normalPayloadJson; }
    public String getPrivateRefsJson() { return privateRefsJson; }
    public ProposalStatus getStatus() { return status; }
    public Instant getCreatedAt() { return createdAt; }
    public String getRemediationAuthorizedBy() { return remediationAuthorizedBy; }
    public Instant getRemediationAuthorizedAt() { return remediationAuthorizedAt; }
}
