package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.api.ApiModels.CreateActionRequest;
import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.integration.GatewayPolicyClient;
import br.com.t3privacyguard.integration.GatewayPolicyClient.GatewayDecision;
import br.com.t3privacyguard.integration.GatewayRemediationClient;
import br.com.t3privacyguard.integration.GatewayRemediationClient.RemediationRequest;
import br.com.t3privacyguard.integration.GatewayRemediationClient.RemediationResult;
import br.com.t3privacyguard.integration.GatewayRemediationClient.VerificationResult;
import br.com.t3privacyguard.integration.GatewayUnavailableException;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
class IncidentServiceTest {
    private static final String POLICY_VERSION = "2026-09-12.1";
    private static final String POLICY_HASH = "a".repeat(64);

    @Autowired IncidentService service;
    @Autowired IncidentRepository incidents;
    @Autowired ActionProposalRepository actions;
    @Autowired PolicyDecisionRepository decisions;
    @Autowired AuditEventRepository audits;
    @Autowired RemediationExecutionRepository remediations;
    @MockitoBean GatewayPolicyClient gateway;
    @MockitoBean GatewayRemediationClient remediationGateway;

    @BeforeEach
    void clear() {
        remediations.deleteAll(); audits.deleteAll(); decisions.deleteAll(); actions.deleteAll(); incidents.deleteAll();
        reset(gateway, remediationGateway);
    }

    @Test void rejectsDuplicateRequestIdAsReplay() {
        var incident = createIncident("Leak"); var input = safeAction("req-1"); service.addAction(incident.id(), input);
        assertThatThrownBy(() -> service.addAction(incident.id(), input)).isInstanceOf(ConflictException.class);
    }

    @Test void rejectsRawPlaceholderOrUnknownPrivateReferenceBeforePersistence() {
        var incident = createIncident("Private data");
        assertThatThrownBy(() -> service.addAction(incident.id(), new CreateActionRequest(
            "raw-1", "notify-security", "incident:test", "incident-notification", "postman-echo.com",
            List.of("incident_id"), List.of("{{profile.verified_contacts.email.value}}")
        ))).isInstanceOf(IllegalArgumentException.class);
        assertThat(actions.count()).isZero();
    }

    @Test void canonicalizesApprovedDestinationBeforePersistence() {
        var incident = createIncident("Destination binding");
        var action = service.addAction(incident.id(), new CreateActionRequest(
            "host-canonical", "revoke-credential", "credential:test", "incident-remediation", "Postman-Echo.COM",
            List.of("incident_id", "credential_id", "reason"), List.of()
        ));
        assertThat(action.host()).isEqualTo("postman-echo.com");
        assertThat(actions.findById(action.id()).orElseThrow().getHost()).isEqualTo("postman-echo.com");
    }

    @Test void rejectsUrlInsteadOfHostnameBeforePersistence() {
        var incident = createIncident("Destination validation");
        assertThatThrownBy(() -> service.addAction(incident.id(), new CreateActionRequest(
            "host-url", "revoke-credential", "credential:test", "incident-remediation", "https://postman-echo.com/post",
            List.of("incident_id", "credential_id", "reason"), List.of()
        ))).isInstanceOf(IllegalArgumentException.class);
        assertThat(actions.count()).isZero();
    }

    @Test void persistsOnlyLogicalPrivateReferenceAndPropagatesPolicyResult() {
        var incident = createIncident("Private data");
        var action = service.addAction(incident.id(), new CreateActionRequest(
            "private-1", "notify-security", "incident:test", "incident-notification", "postman-echo.com",
            List.of("incident_id", "severity", "summary"), List.of("verified_email")
        ));
        when(gateway.evaluate(any())).thenReturn(new GatewayDecision(
            "private-1", DecisionType.ALLOW, "POLICY_ALLOW", "Allowed",
            List.of("incident_id", "severity", "summary"), List.of(), List.of("verified_email"), List.of(),
            POLICY_VERSION, POLICY_HASH, true
        ));
        var decision = service.evaluate(incident.id(), action.id());
        assertThat(service.listActions(incident.id()).get(0).privateRefs()).containsExactly("verified_email");
        assertThat(decision.allowedPrivateRefs()).containsExactly("verified_email");
        assertThat(decision.policyVersion()).isEqualTo(POLICY_VERSION);
        assertThat(decision.policyHash()).isEqualTo(POLICY_HASH);
    }

    @Test void denyCannotAuthorizeRemediation() {
        var incident = createIncident("Attack"); var action = service.addAction(incident.id(), safeAction("req-2"));
        when(gateway.evaluate(any())).thenReturn(decision("req-2", DecisionType.DENY, "HOST_NOT_ALLOWED", List.of(), List.of()));
        service.evaluate(incident.id(), action.id());
        assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id())).isInstanceOf(PolicyDeniedException.class);
    }

    @Test void supportedRemediationWithoutApprovedDestinationFailsClosed() {
        var incident = createIncident("Missing destination");
        var action = service.addAction(incident.id(), new CreateActionRequest(
            "host-missing", "revoke-credential", "credential:test", "incident-remediation", null,
            List.of("incident_id", "credential_id", "reason"), List.of()
        ));
        allow("host-missing");
        service.evaluate(incident.id(), action.id());
        assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id()))
            .isInstanceOf(PolicyDeniedException.class)
            .hasMessageContaining("approved destination");
        verify(remediationGateway, times(0)).execute(any(), anyString());
    }

    @Test void persistedDecisionPreventsSecondGatewayExecution() {
        var incident = createIncident("Attack");
        var action = service.addAction(incident.id(), new CreateActionRequest(
            "req-3", "create-incident", "incident:test", "incident-recording", null,
            List.of("incident_id", "severity", "summary"), List.of()
        ));
        when(gateway.evaluate(any())).thenReturn(decision("req-3", DecisionType.ALLOW, "POLICY_ALLOW", List.of("incident_id"), List.of()));
        service.evaluate(incident.id(), action.id()); service.evaluate(incident.id(), action.id());
        verify(gateway, times(1)).evaluate(any());
    }

    @Test void policyOnlyActionsRemainEvaluableButCannotEnterProtectedExecution() {
        List<CreateActionRequest> unsupported = List.of(
            new CreateActionRequest("req-isolate", "isolate-account", "account:demo", "incident-remediation", "postman-echo.com", List.of("incident_id", "account_id", "reason"), List.of()),
            new CreateActionRequest("req-record", "create-incident", "incident:demo", "incident-recording", null, List.of("incident_id", "severity", "summary", "source"), List.of()),
            new CreateActionRequest("req-notify", "notify-security", "incident:demo", "incident-notification", "postman-echo.com", List.of("incident_id", "severity", "summary"), List.of("verified_email"))
        );

        for (CreateActionRequest input : unsupported) {
            var incident = createIncident("Policy-only " + input.action());
            var action = service.addAction(incident.id(), input);
            when(gateway.evaluate(any())).thenReturn(new GatewayDecision(
                input.requestId(), DecisionType.ALLOW, "POLICY_ALLOW", "Allowed",
                input.fields(), List.of(), input.privateRefs(), List.of(), POLICY_VERSION, POLICY_HASH, true
            ));

            assertThat(service.evaluate(incident.id(), action.id()).decision()).isEqualTo(DecisionType.ALLOW);
            assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id()))
                .isInstanceOf(PolicyDeniedException.class)
                .hasMessage("Protected remediation is not implemented for this action");
            assertThat(actions.findById(action.id()).orElseThrow().getStatus().name()).isEqualTo("EVALUATED");
        }

        assertThat(remediations.count()).isZero();
        verify(remediationGateway, times(0)).execute(any(), anyString());
        verify(remediationGateway, times(0)).verify(anyString(), anyString());
    }

    @Test void executionCarriesThePersistedApprovedDestination() {
        var context = authorizedAction("req-host-bound");
        when(remediationGateway.execute(any(), anyString())).thenReturn(remediation("req-host-bound", 202, "op-host"));
        when(remediationGateway.verify("req-host-bound", "op-host")).thenReturn(new VerificationResult("req-host-bound", "VERIFIED", "REVOKED"));

        service.executeRemediation(context.incidentId(), context.actionId());

        ArgumentCaptor<RemediationRequest> request = ArgumentCaptor.forClass(RemediationRequest.class);
        verify(remediationGateway).execute(request.capture(), anyString());
        assertThat(request.getValue().approvedHost()).isEqualTo("postman-echo.com");
    }

    @Test void completedRequiresIndependentReadBackAndReplayDoesNotReexecute() {
        var context = authorizedAction("req-4");
        when(remediationGateway.execute(any(), anyString())).thenReturn(remediation("req-4", 202, "op-1"));
        when(remediationGateway.verify("req-4", "op-1")).thenReturn(new VerificationResult("req-4", "VERIFIED", "REVOKED"));

        var first = service.executeRemediation(context.incidentId(), context.actionId());
        var second = service.executeRemediation(context.incidentId(), context.actionId());

        assertThat(first.state()).isEqualTo("COMPLETED");
        assertThat(second.state()).isEqualTo("COMPLETED");
        assertThat(second.operationId()).isEqualTo("op-1");
        assertThat(second.verificationAttempts()).isEqualTo(1);
        verify(remediationGateway, times(1)).execute(any(), anyString());
        verify(remediationGateway, times(1)).verify("req-4", "op-1");
    }

    @Test void concurrentRequestsProduceOnlyOneExternalExecution() throws Exception {
        var context = authorizedAction("req-concurrent");
        when(remediationGateway.execute(any(), anyString())).thenReturn(remediation("req-concurrent", 202, "op-concurrent"));
        when(remediationGateway.verify("req-concurrent", "op-concurrent")).thenReturn(new VerificationResult("req-concurrent", "VERIFIED", "REVOKED"));
        CountDownLatch start = new CountDownLatch(1);

        CompletableFuture<?> first = CompletableFuture.supplyAsync(() -> {
            await(start); return service.executeRemediation(context.incidentId(), context.actionId());
        });
        CompletableFuture<?> second = CompletableFuture.supplyAsync(() -> {
            await(start); return service.executeRemediation(context.incidentId(), context.actionId());
        });
        start.countDown();
        CompletableFuture.allOf(first, second).get(10, TimeUnit.SECONDS);

        verify(remediationGateway, times(1)).execute(any(), anyString());
        assertThat(remediations.findByActionProposalId(context.actionId())).isPresent();
        assertThat(remediations.findByActionProposalId(context.actionId()).orElseThrow().getStatus().name()).isEqualTo("COMPLETED");
    }

    @Test void acceptedHttpWithoutVerifiedExternalStateIsUnverifiedNotCompleted() {
        var context = authorizedAction("req-lying-200");
        when(remediationGateway.execute(any(), anyString())).thenReturn(remediation("req-lying-200", 200, "op-lie"));
        when(remediationGateway.verify("req-lying-200", "op-lie")).thenReturn(new VerificationResult("req-lying-200", "UNVERIFIED", "ACTIVE"));

        var result = service.executeRemediation(context.incidentId(), context.actionId());

        assertThat(result.state()).isEqualTo("UNVERIFIED");
        assertThat(result.failureCode()).isEqualTo("EXTERNAL_STATE_NOT_VERIFIED");
        verify(remediationGateway, times(1)).execute(any(), anyString());
    }

    @Test void ambiguousExecutionOutcomeIsPersistedAndNeverAutomaticallyRetried() {
        var context = authorizedAction("req-timeout");
        when(remediationGateway.execute(any(), anyString())).thenThrow(new GatewayUnavailableException("timeout after send"));

        var first = service.executeRemediation(context.incidentId(), context.actionId());
        var second = service.executeRemediation(context.incidentId(), context.actionId());

        assertThat(first.state()).isEqualTo("UNVERIFIED");
        assertThat(first.failureCode()).isEqualTo("EXECUTION_RESULT_UNKNOWN");
        assertThat(second.state()).isEqualTo("UNVERIFIED");
        verify(remediationGateway, times(1)).execute(any(), anyString());
    }

    @Test void verificationOutageDoesNotTriggerSecondEgressAndCanBeRechecked() {
        var context = authorizedAction("req-verification-outage");
        when(remediationGateway.execute(any(), anyString())).thenReturn(remediation("req-verification-outage", 202, "op-outage"));
        when(remediationGateway.verify("req-verification-outage", "op-outage"))
            .thenThrow(new GatewayUnavailableException("verification offline"))
            .thenReturn(new VerificationResult("req-verification-outage", "VERIFIED", "REVOKED"));

        var first = service.executeRemediation(context.incidentId(), context.actionId());
        var second = service.verifyRemediation(context.incidentId(), context.actionId());

        assertThat(first.state()).isEqualTo("UNVERIFIED");
        assertThat(second.state()).isEqualTo("COMPLETED");
        assertThat(second.verificationAttempts()).isEqualTo(2);
        verify(remediationGateway, times(1)).execute(any(), anyString());
        verify(remediationGateway, times(2)).verify("req-verification-outage", "op-outage");
    }

    @Test void gatewayUnavailableFailsClosedWithoutPersistingDecision() {
        var incident = createIncident("Gateway failure"); var action = service.addAction(incident.id(), safeAction("req-5"));
        when(gateway.evaluate(any())).thenThrow(new GatewayUnavailableException("gateway unavailable"));
        assertThatThrownBy(() -> service.evaluate(incident.id(), action.id())).isInstanceOf(GatewayUnavailableException.class);
        assertThat(decisions.count()).isZero();
        assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id())).isInstanceOf(ConflictException.class);
    }

    @Test void mismatchedPolicyResponseRequestIdFailsClosed() {
        var incident = createIncident("Tampered response"); var action = service.addAction(incident.id(), safeAction("req-6"));
        when(gateway.evaluate(any())).thenReturn(decision("another-request", DecisionType.ALLOW, "POLICY_ALLOW", List.of("incident_id", "credential_id", "reason"), List.of()));
        assertThatThrownBy(() -> service.evaluate(incident.id(), action.id())).isInstanceOf(IllegalStateException.class).hasMessageContaining("request id mismatch");
        assertThat(decisions.count()).isZero();
    }

    @Test void remediationCannotExecuteBeforeExplicitAuthorization() {
        var incident = createIncident("Unauthorized execution"); var action = service.addAction(incident.id(), safeAction("req-7"));
        allow("req-7"); service.evaluate(incident.id(), action.id());
        assertThatThrownBy(() -> service.executeRemediation(incident.id(), action.id())).isInstanceOf(PolicyDeniedException.class);
        verify(remediationGateway, times(0)).execute(any(), anyString());
    }

    @Test void mismatchedExecutionRequestIdBecomesUnverifiedAndIsNotRetried() {
        var context = authorizedAction("req-8");
        when(remediationGateway.execute(any(), anyString())).thenReturn(remediation("another-request", 202, "op-8"));
        var result = service.executeRemediation(context.incidentId(), context.actionId());
        assertThat(result.state()).isEqualTo("UNVERIFIED");
        assertThat(result.failureCode()).isEqualTo("REQUEST_ID_MISMATCH");
        verify(remediationGateway, times(1)).execute(any(), anyString());
        verify(remediationGateway, times(0)).verify(anyString(), anyString());
    }

    private AuthorizedAction authorizedAction(String requestId) {
        var incident = createIncident("Credential");
        var action = service.addAction(incident.id(), safeAction(requestId));
        allow(requestId);
        service.evaluate(incident.id(), action.id());
        service.authorizeRemediation(incident.id(), action.id());
        return new AuthorizedAction(incident.id(), action.id());
    }

    private br.com.t3privacyguard.api.ApiModels.IncidentResponse createIncident(String title) {
        return service.createIncident(new CreateIncidentRequest(title, Severity.CRITICAL, "Synthetic incident", "adversarial-test"));
    }

    private CreateActionRequest safeAction(String requestId) {
        return new CreateActionRequest(requestId, "revoke-credential", "credential:test", "incident-remediation", "postman-echo.com", List.of("incident_id", "credential_id", "reason"), List.of());
    }

    private GatewayDecision decision(String requestId, DecisionType type, String code, List<String> allowed, List<String> redacted) {
        return new GatewayDecision(
            requestId, type, code, type == DecisionType.ALLOW ? "Allowed" : "Denied", allowed, redacted, List.of(), List.of(),
            POLICY_VERSION, POLICY_HASH, true
        );
    }

    private RemediationResult remediation(String requestId, int httpCode, String operationId) {
        return new RemediationResult(requestId, "PENDING_VERIFICATION", httpCode, operationId, POLICY_VERSION, POLICY_HASH);
    }

    private void allow(String requestId) {
        when(gateway.evaluate(any())).thenReturn(decision(requestId, DecisionType.ALLOW, "POLICY_ALLOW", List.of("incident_id", "credential_id", "reason"), List.of()));
    }

    private static void await(CountDownLatch latch) {
        try { latch.await(5, TimeUnit.SECONDS); }
        catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
    }

    private record AuthorizedAction(String incidentId, String actionId) {}
}
