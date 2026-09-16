package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.persistence.SecurityRemediationOperationEntity;
import br.com.t3privacyguard.persistence.SecurityRemediationOperationRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class SecurityRemediationAdapterServiceTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    SecurityRemediationOperationRepository operations;

    @InjectMocks
    SecurityRemediationAdapterService service;

    @Test
    void acceptsActualT3nRevokeEgressAndPersistsOnlyOperationalMetadata() throws Exception {
        when(operations.findByRequestId("req-1")).thenReturn(Optional.empty());
        JsonNode body = json(revokeBody("req-1", "credential exposed"));

        var result = service.execute("req-1", body);

        assertThat(result.operationId()).startsWith("op_");
        ArgumentCaptor<SecurityRemediationOperationEntity> persisted = ArgumentCaptor.forClass(SecurityRemediationOperationEntity.class);
        verify(operations).saveAndFlush(persisted.capture());
        assertThat(persisted.getValue().getRequestId()).isEqualTo("req-1");
        assertThat(persisted.getValue().getAction()).isEqualTo("revoke-credential");
        assertThat(persisted.getValue().getState()).isEqualTo("REVOKED");
        assertThat(persisted.getValue().isRecipientResolved()).isFalse();
    }

    @Test
    void acceptsActualT3nNotifyEgressWithoutPersistingRecipient() throws Exception {
        when(operations.findByRequestId("req-notify")).thenReturn(Optional.empty());
        JsonNode body = json("""
            {
              "request_id":"req-notify",
              "action":"notify-security",
              "resource":"incident:inc-2",
              "purpose":"incident-notification",
              "incident_id":"inc-2",
              "severity":"HIGH",
              "summary":"SENTINEL_MUST_EGRESS",
              "recipient":"security@example.test"
            }
            """);

        service.execute("req-notify", body);

        ArgumentCaptor<SecurityRemediationOperationEntity> persisted = ArgumentCaptor.forClass(SecurityRemediationOperationEntity.class);
        verify(operations).saveAndFlush(persisted.capture());
        assertThat(persisted.getValue().getAction()).isEqualTo("notify-security");
        assertThat(persisted.getValue().getState()).isEqualTo("DELIVERED");
        assertThat(persisted.getValue().isRecipientResolved()).isTrue();
        assertThat(persisted.getValue().isMustEgressSeen()).isTrue();
        assertThat(persisted.getValue().isMustNotEgressSeen()).isFalse();
    }

    @Test
    void rejectsMissingIdempotencyKeyBeforePersistence() throws Exception {
        JsonNode body = json(revokeBody("req-1", "credential exposed"));

        assertStatus(HttpStatus.BAD_REQUEST, () -> service.execute(null, body));
        verify(operations, never()).saveAndFlush(any());
    }

    @Test
    void rejectsRequestIdThatDoesNotMatchIdempotencyKey() throws Exception {
        JsonNode body = json(revokeBody("req-body", "credential exposed"));

        assertStatus(HttpStatus.CONFLICT, () -> service.execute("req-header", body));
        verify(operations, never()).saveAndFlush(any());
    }

    @Test
    void rejectsUnexpectedExecutionFields() throws Exception {
        JsonNode body = json("""
            {
              "request_id":"req-extra",
              "action":"revoke-credential",
              "resource":"credential:cred-1",
              "purpose":"incident-remediation",
              "incident_id":"inc-1",
              "credential_id":"cred-1",
              "reason":"credential exposed",
              "private_value":"must-not-pass"
            }
            """);

        assertStatus(HttpStatus.BAD_REQUEST, () -> service.execute("req-extra", body));
        verify(operations, never()).saveAndFlush(any());
    }

    @Test
    void rejectsWrongActionPurposeBinding() throws Exception {
        JsonNode body = json("""
            {
              "request_id":"req-purpose",
              "action":"revoke-credential",
              "resource":"credential:cred-1",
              "purpose":"incident-notification",
              "incident_id":"inc-1",
              "credential_id":"cred-1",
              "reason":"credential exposed"
            }
            """);

        assertStatus(HttpStatus.BAD_REQUEST, () -> service.execute("req-purpose", body));
        verify(operations, never()).saveAndFlush(any());
    }

    @Test
    void retryWithSameRequestAndActionReturnsSameOperation() throws Exception {
        SecurityRemediationOperationEntity existing = operation("op_existing", "req-retry", "revoke-credential", "REVOKED", false);
        when(operations.findByRequestId("req-retry")).thenReturn(Optional.of(existing));
        JsonNode body = json(revokeBody("req-retry", "retry"));

        var result = service.execute("req-retry", body);

        assertThat(result.operationId()).isEqualTo("op_existing");
        verify(operations, never()).saveAndFlush(any());
    }

    @Test
    void reuseOfIdempotencyKeyForAnotherActionIsRejected() throws Exception {
        SecurityRemediationOperationEntity existing = operation("op_existing", "req-conflict", "revoke-credential", "REVOKED", false);
        when(operations.findByRequestId("req-conflict")).thenReturn(Optional.of(existing));
        JsonNode body = json("""
            {
              "request_id":"req-conflict",
              "action":"notify-security",
              "resource":"incident:inc-2",
              "purpose":"incident-notification",
              "incident_id":"inc-2",
              "severity":"HIGH",
              "summary":"notify",
              "recipient":"security@example.test"
            }
            """);

        assertStatus(HttpStatus.CONFLICT, () -> service.execute("req-conflict", body));
    }

    @Test
    void verificationReturnsClosedReadBackContract() throws Exception {
        SecurityRemediationOperationEntity existing = operation("op_verify", "req-verify", "notify-security", "DELIVERED", true);
        when(operations.findById("op_verify")).thenReturn(Optional.of(existing));
        JsonNode body = json("""
            {
              "request_id":"req-verify",
              "operation_id":"op_verify",
              "action":"notify-security",
              "expected_state":"DELIVERED"
            }
            """);

        var result = service.verify(body);

        assertThat(result.operationId()).isEqualTo("op_verify");
        assertThat(result.state()).isEqualTo("DELIVERED");
        assertThat(result.recipientResolved()).isTrue();
        assertThat(result.payloadProof().mustEgressSeen()).isFalse();
        assertThat(result.payloadProof().mustNotEgressSeen()).isFalse();
    }

    @Test
    void verificationFailsClosedWhenRequestDoesNotOwnOperation() throws Exception {
        SecurityRemediationOperationEntity existing = operation("op_verify", "req-owner", "revoke-credential", "REVOKED", false);
        when(operations.findById("op_verify")).thenReturn(Optional.of(existing));
        JsonNode body = json("""
            {
              "request_id":"req-other",
              "operation_id":"op_verify",
              "action":"revoke-credential",
              "expected_state":"REVOKED"
            }
            """);

        assertStatus(HttpStatus.CONFLICT, () -> service.verify(body));
    }

    @Test
    void verificationRejectsOperationIdOutsideRustCharset() throws Exception {
        JsonNode body = json("""
            {
              "request_id":"req-verify",
              "operation_id":"op.invalid",
              "action":"revoke-credential",
              "expected_state":"REVOKED"
            }
            """);

        assertStatus(HttpStatus.BAD_REQUEST, () -> service.verify(body));
    }

    private JsonNode json(String value) throws Exception {
        return objectMapper.readTree(value);
    }

    private static String revokeBody(String requestId, String reason) {
        return """
            {
              "request_id":"%s",
              "action":"revoke-credential",
              "resource":"credential:cred-1",
              "purpose":"incident-remediation",
              "incident_id":"inc-1",
              "credential_id":"cred-1",
              "reason":"%s"
            }
            """.formatted(requestId, reason);
    }

    private static SecurityRemediationOperationEntity operation(
        String operationId,
        String requestId,
        String action,
        String state,
        boolean recipientResolved
    ) {
        return new SecurityRemediationOperationEntity(
            operationId,
            requestId,
            action,
            state,
            recipientResolved,
            false,
            false,
            Instant.parse("2026-09-16T17:00:00Z")
        );
    }

    private static void assertStatus(HttpStatus expected, ThrowingRunnable invocation) {
        assertThatThrownBy(invocation::run)
            .isInstanceOf(ResponseStatusException.class)
            .extracting(error -> ((ResponseStatusException) error).getStatusCode().value())
            .isEqualTo(expected.value());
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
