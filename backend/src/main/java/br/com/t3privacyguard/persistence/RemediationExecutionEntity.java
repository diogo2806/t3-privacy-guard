package br.com.t3privacyguard.persistence;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name="remediation_executions",uniqueConstraints=@UniqueConstraint(name="uk_remediation_action",columnNames="action_proposal_id"))
public class RemediationExecutionEntity {
    @Id private String id;
    @Column(name="action_proposal_id",nullable=false,length=36) private String actionProposalId;
    @Column(name="request_id",nullable=false,length=128) private String requestId;
    @Column(nullable=false,length=24) private String status;
    @Column(name="http_code",nullable=false) private int httpCode;
    @Column(name="operation_id",length=200) private String operationId;
    @Column(nullable=false) private Instant executedAt;
    protected RemediationExecutionEntity(){}
    public RemediationExecutionEntity(String id,String actionProposalId,String requestId,String status,int httpCode,String operationId,Instant executedAt){this.id=id;this.actionProposalId=actionProposalId;this.requestId=requestId;this.status=status;this.httpCode=httpCode;this.operationId=operationId;this.executedAt=executedAt;}
    public String getActionProposalId(){return actionProposalId;} public String getRequestId(){return requestId;} public String getStatus(){return status;} public int getHttpCode(){return httpCode;} public String getOperationId(){return operationId;} public Instant getExecutedAt(){return executedAt;}
}
