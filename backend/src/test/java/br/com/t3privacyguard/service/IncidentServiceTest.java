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
import br.com.t3privacyguard.security.RemediationAuthorizationSigner;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest
class IncidentServiceTest {
    private static final String POLICY_VERSION = "2026-09-12.1";
    private static final String POLICY_HASH = "a".repeat(64);
    private static final String OPERATOR = "ops-reviewer";

    @Autowired IncidentService service;
    @Autowired IncidentRepository incidents;
    @Autowired ActionProposalRepository actions;
    @Autowired PolicyDecisionRepository decisions;
    @Autowired AuditEventRepository audits;
    @Autowired RemediationExecutionRepository remediations;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean GatewayPolicyClient gateway;
    @MockitoBean GatewayRemediationClient remediationGateway;

    @BeforeEach
    void clear() {
        remediations.deleteAll(); audits.deleteAll(); decisions.deleteAll(); actions.deleteAll(); incidents.deleteAll();
        reset(gateway, remediationGateway);
        when(remediationGateway.requireExecutorDid()).thenReturn("did:t3n:protected-executor-test");
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
        var action = service.addAction(incident.id(), notifyAction("private-1"));
        when(gateway.evaluate(any())).thenReturn(notifyDecision("private-1"));
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
        assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id(), OPERATOR)).isInstanceOf(PolicyDeniedException.class);
    }

    @Test void authorizationPersistsAuthenticatedPrincipalAndRetryKeepsOriginalTimestamp() {
        var incident = createIncident("Approval provenance");
        var action = service.addAction(incident.id(), safeAction("req-provenance"));
        allow("req-provenance");
        service.evaluate(incident.id(), action.id());

        var first = service.authorizeRemediation(incident.id(), action.id(), "  ops-reviewer  ");
        var persisted = actions.findById(action.id()).orElseThrow();
        var firstTimestamp = persisted.getRemediationAuthorizedAt();
        var second = service.authorizeRemediation(incident.id(), action.id(), OPERATOR);

        assertThat(first.authorizedBy()).isEqualTo(OPERATOR);
        assertThat(first.authorizedAt()).isNotNull();
        assertThat(second.authorizedBy()).isEqualTo(OPERATOR);
        assertThat(second.authorizedAt()).isEqualTo(firstTimestamp);
        assertThat(actions.findById(action.id()).orElseThrow().getRemediationAuthorizedAt()).isEqualTo(firstTimestamp);
        assertThat(audits.findAll()).filteredOn(event -> "REMEDIATION_AUTHORIZED".equals(event.getType())).hasSize(1);
        assertThat(audits.findAll()).anyMatch(event -> event.getMessage().contains("authorized by " + OPERATOR));
    }

    @Test void differentOperatorCannotOverwriteExistingAuthorization() {
        var incident = createIncident("Approval conflict");
        var action = service.addAction(incident.id(), safeAction("req-approval-conflict"));
        allow("req-approval-conflict");
        service.evaluate(incident.id(), action.id());
        service.authorizeRemediation(incident.id(), action.id(), OPERATOR);
        var firstTimestamp = actions.findById(action.id()).orElseThrow().getRemediationAuthorizedAt();

        assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id(), "other-operator"))
            .isInstanceOf(ConflictException.class)
            .hasMessageContaining("another operator");
        var persisted = actions.findById(action.id()).orElseThrow();
        assertThat(persisted.getRemediationAuthorizedBy()).isEqualTo(OPERATOR);
        assertThat(persisted.getRemediationAuthorizedAt()).isEqualTo(firstTimestamp);
    }

    @Test void supportedRemediationWithoutApprovedDestinationFailsClosed() {
        var incident = createIncident("Missing destination");
        var action = service.addAction(incident.id(), new CreateActionRequest(
            "host-missing", "revoke-credential", "credential:test", "incident-remediation", null,
            List.of("incident_id", "credential_id", "reason"), List.of()
        ));
        allow("host-missing");
        service.evaluate(incident.id(), action.id());
        assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id(), OPERATOR))
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
            new CreateActionRequest("req-record", "create-incident", "incident:demo", "incident-recording", null, List.of("incident_id", "severity", "summary", "source"), List.of())
        );

        for (CreateActionRequest input : unsupported) {
            var incident = createIncident("Policy-only " + input.action());
            var action = service.addAction(incident.id(), input);
            when(gateway.evaluate(any())).thenReturn(new GatewayDecision(
                input.requestId(), DecisionType.ALLOW, "POLICY_ALLOW", "Allowed",
                input.fields(), List.of(), input.privateRefs(), List.of(), POLICY_VERSION, POLICY_HASH, true
            ));

            assertThat(service.evaluate(incident.id(), action.id()).decision()).isEqualTo(DecisionType.ALLOW);
            assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id(), OPERATOR))
                .isInstanceOf(PolicyDeniedException.class)
                .hasMessage("Protected remediation is not implemented for this action");
            assertThat(actions.findById(action.id()).orElseThrow().getStatus().name()).isEqualTo("EVALUATED");
        }

        assertThat(remediations.count()).isZero();
        verify(remediationGateway, times(0)).execute(any(), anyString());
        verify(remediationGateway, times(0)).verify(anyString(), anyString());
        verify(remediationGateway, times(0)).verifyDelivery(anyString(), anyString());
    }

    @Test void notifySecurityUsesLogicalPrivateReferenceAndRequiresVerifiedDelivery() {
        var incident = createIncident("Private notification");
        var action = service.addAction(incident.id(), notifyAction("req-notify"));
        when(gateway.evaluate(any())).thenReturn(notifyDecision("req-notify"));
        service.evaluate(incident.id(), action.id());
        service.authorizeRemediation(incident.id(), action.id(), OPERATOR);
        when(remediationGateway.execute(any(), anyString())).thenReturn(remediation("req-notify", 202, "op-notify"));
        when(remediationGateway.verifyDelivery("req-notify", "op-notify"))
            .thenReturn(new VerificationResult("req-notify", "VERIFIED", "DELIVERED", true));

        var result = service.executeRemediation(incident.id(), action.id());

        assertThat(result.state()).isEqualTo("COMPLETED");
        ArgumentCaptor<RemediationRequest> request = ArgumentCaptor.forClass(RemediationRequest.class);
        verify(remediationGateway).execute(request.capture(), anyString());
        assertThat(request.getValue().action()).isEqualTo("notify-security");
        assertThat(request.getValue().purpose()).isEqualTo("incident-notification");
        assertThat(request.getValue().privateRefs()).containsExactly("verified_email");
        assertThat(request.getValue().operatorPrincipalHash()).isEqualTo(RemediationAuthorizationSigner.operatorPrincipalHash(OPERATOR));
        assertThat(request.getValue().authorizationRecordedAt()).isPositive();
        verify(remediationGateway, times(1)).verifyDelivery("req-notify", "op-notify");
        verify(remediationGateway, times(0)).verify(anyString(), anyString());
    }

    @Test void notifySecurityWithoutConfirmedPrivateResolutionRemainsUnverified() {
        var incident = createIncident("Private notification unresolved");
        var action = service.addAction(incident.id(), notifyAction("req-notify-unresolved"));
        when(gateway.evaluate(any())).thenReturn(notifyDecision("req-notify-unresolved"));
        service.evaluate(incident.id(), action.id());
        service.authorizeRemediation(incident.id(), action.id(), OPERATOR);
        when(remediationGateway.execute(any(), anyString())).thenReturn(remediation("req-notify-unresolved", 202, "op-notify-unresolved"));
        when(remediationGateway.verifyDelivery("req-notify-unresolved", "op-notify-unresolved"))
            .thenReturn(new VerificationResult("req-notify-unresolved", "VERIFIED", "DELIVERED", false));

        var result = service.executeRemediation(incident.id(), action.id());

        assertThat(result.state()).isEqualTo("UNVERIFIED");
        assertThat(result.failureCode()).isEqualTo("EXTERNAL_STATE_NOT_VERIFIED");
    }

    @Test void notifySecurityMissingAllowedPrivateReferenceCannotAuthorize() {
        var incident = createIncident("Private reference removed");
        var action = service.addAction(incident.id(), notifyAction("req-notify-private-deny"));
        when(gateway.evaluate(any())).thenReturn(new GatewayDecision(
            "req-notify-private-deny", DecisionType.ALLOW, "POLICY_ALLOW", "Allowed",
            List.of("incident_id", "severity", "summary"), List.of(), List.of(), List.of("verified_email"),
            POLICY_VERSION, POLICY_HASH, true
        ));
        service.evaluate(incident.id(), action.id());

        assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id(), OPERATOR))
            .isInstanceOf(PolicyDeniedException.class)
            .hasMessageContaining("verified_email");
        verify(remediationGateway, times(0)).execute(any(), anyString());
    }

    @Test void executionCarriesApprovedDestinationAndHumanAuthorizationBinding() {
        var context = authorizedAction("req-host-bound");
        when(remediationGateway.execute(any(), anyString())).thenReturn(remediation("req-host-bound", 202, "op-host"));
        when(remediationGateway.verify("req-host-bound", "op-host")).thenReturn(new VerificationResult("req-host-bound", "VERIFIED", "REVOKED"));

        service.executeRemediation(context.incidentId(), context.actionId());

        ArgumentCaptor<RemediationRequest> request = ArgumentCaptor.forClass(RemediationRequest.class);
        verify(remediationGateway).execute(request.capture(), anyString());
        assertThat(request.getValue().approvedHost()).isEqualTo("postman-echo.com");
        assertThat(request.getValue().operatorPrincipalHash()).isEqualTo(RemediationAuthorizationSigner.operatorPrincipalHash(OPERATOR));
        assertThat(request.getValue().authorizationRecordedAt()).isPositive();
    }

    @Test void legacyAuthorizationWithoutProvenanceCannotExecute() {
        var context = authorizedAction("req-legacy-authorization");
        jdbc.update("update action_proposals set remediation_authorized_by = null, remediation_authorized_at = null where id = ?", context.actionId());

        assertThatThrownBy(() -> service.executeRemediation(context.incidentId(), context.actionId()))
            .isInstanceOf(PolicyDeniedException.class)
            .hasMessageContaining("provenance is not bound");
        verify(remediationGateway, times(0)).execute(any(), anyString());
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
        assertThatThrownBy(() -> service.authorizeRemediation(incident.id(), action.id(), OPERATOR)).isInstanceOf(ConflictException.class);
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
        service.authorizeRemediation(incident.id(), action.id(), OPERATOR);
        return new AuthorizedAction(incident.id(), action.id());
    }

    private br.com.t3privacyguard.api.ApiModels.IncidentResponse createIncident(String title) {
        return service.createIncident(new CreateIncidentRequest(title, Severity.CRITICAL, "Synthetic incident", "adversarial-test"));
    }

    private CreateActionRequest safeAction(String requestId) {
        return new CreateActionRequest(requestId, "revoke-credential", "credential:test", "incident-remediation", "postman-echo.com", List.of("incident_id", "credential_id", "reason"), List.of());
    }

    private CreateActionRequest notifyAction(String requestId) {
        return new CreateActionRequest(requestId, "notify-security", "incident:test", "incident-notification", "postman-echo.com",
            List.of("incident_id", "severity", "summary"), List.of("verified_email"));
    }

    private GatewayDecision decision(String requestId, DecisionType type, String code, List<String> allowed, List<String> redacted) {
        return new GatewayDecision(
            requestId, type, code, type == DecisionType.ALLOW ? "Allowed" : "Denied", allowed, redacted, List.of(), List.of(),
            POLICY_VERSION, POLICY_HASH, true
        );
    }

    private GatewayDecision notifyDecision(String requestId) {
        return new GatewayDecision(
            requestId, DecisionType.ALLOW, "POLICY_ALLOW", "Allowed",
            List.of("incident_id", "severity", "summary"), List.of(), List.of("verified_email"), List.of(),
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
