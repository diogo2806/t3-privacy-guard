package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import br.com.t3privacyguard.api.ApiModels.*;
import br.com.t3privacyguard.domain.*;
import br.com.t3privacyguard.integration.*;
import br.com.t3privacyguard.integration.GatewayPolicyClient.GatewayDecision;
import br.com.t3privacyguard.integration.GatewayRemediationClient.RemediationResult;
import br.com.t3privacyguard.persistence.*;
import java.util.List;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(properties="spring.datasource.url=jdbc:h2:mem:incident-test;DB_CLOSE_DELAY=-1")
class IncidentServiceTest {
 @Autowired IncidentService service; @Autowired IncidentRepository incidents; @Autowired ActionProposalRepository actions; @Autowired PolicyDecisionRepository decisions; @Autowired AuditEventRepository audits; @Autowired RemediationExecutionRepository remediations; @MockitoBean GatewayPolicyClient gateway; @MockitoBean GatewayRemediationClient remediationGateway;
 @BeforeEach void clear(){remediations.deleteAll();audits.deleteAll();decisions.deleteAll();actions.deleteAll();incidents.deleteAll();reset(gateway,remediationGateway);}
 @Test void rejectsDuplicateRequestIdAsReplay(){var i=service.createIncident(new CreateIncidentRequest("Leak",Severity.CRITICAL,"Synthetic incident","test"));var input=new CreateActionRequest("req-1","revoke-credential","credential:test","incident-remediation","postman-echo.com",List.of("incident_id","credential_id","reason"));service.addAction(i.id(),input);assertThatThrownBy(()->service.addAction(i.id(),input)).isInstanceOf(ConflictException.class);}
 @Test void denyCannotAuthorizeRemediation(){var i=service.createIncident(new CreateIncidentRequest("Attack",Severity.CRITICAL,"Synthetic incident","test"));var a=service.addAction(i.id(),new CreateActionRequest("req-2","revoke-credential","credential:test","incident-remediation","postman-echo.com",List.of("incident_id","credential_id")));when(gateway.evaluate(any())).thenReturn(new GatewayDecision("req-2",DecisionType.DENY,"HOST_NOT_ALLOWED","Denied",List.of(),List.of()));service.evaluate(i.id(),a.id());assertThatThrownBy(()->service.authorizeRemediation(i.id(),a.id())).isInstanceOf(PolicyDeniedException.class);}
 @Test void persistedDecisionPreventsSecondGatewayExecution(){var i=service.createIncident(new CreateIncidentRequest("Attack",Severity.HIGH,"Synthetic incident","test"));var a=service.addAction(i.id(),new CreateActionRequest("req-3","create-incident","incident:test","incident-recording",null,List.of("incident_id","severity","summary")));when(gateway.evaluate(any())).thenReturn(new GatewayDecision("req-3",DecisionType.ALLOW,"POLICY_ALLOW","Allowed",List.of("incident_id"),List.of()));service.evaluate(i.id(),a.id());service.evaluate(i.id(),a.id());verify(gateway,times(1)).evaluate(any());}
 @Test void protectedRemediationIsIdempotent(){var i=service.createIncident(new CreateIncidentRequest("Credential",Severity.CRITICAL,"Synthetic incident","test"));var a=service.addAction(i.id(),new CreateActionRequest("req-4","revoke-credential","credential:test","incident-remediation","postman-echo.com",List.of("incident_id","credential_id","reason")));when(gateway.evaluate(any())).thenReturn(new GatewayDecision("req-4",DecisionType.ALLOW,"POLICY_ALLOW","Allowed",List.of("incident_id","credential_id","reason"),List.of()));service.evaluate(i.id(),a.id());service.authorizeRemediation(i.id(),a.id());when(remediationGateway.execute(any())).thenReturn(new RemediationResult("req-4","COMPLETED",201,"op-1"));var first=service.executeRemediation(i.id(),a.id());var second=service.executeRemediation(i.id(),a.id());assertThat(second.httpCode()).isEqualTo(first.httpCode());assertThat(second.operationId()).isEqualTo("op-1");verify(remediationGateway,times(1)).execute(any());}
}
