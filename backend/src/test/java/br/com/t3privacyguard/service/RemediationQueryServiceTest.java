package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class RemediationQueryServiceTest {
    @Autowired RemediationQueryService query;
    @Autowired RemediationExecutionCoordinator coordinator;
    @Autowired ActionProposalRepository actions;
    @Autowired RemediationExecutionRepository executions;

    @BeforeEach
    void clear() {
        executions.deleteAll();
        actions.deleteAll();
    }

    @Test
    void returnsPersistedStateWithoutTriggeringExecutionOrVerification() {
        actions.saveAndFlush(action("action-1", "incident-1", "request-1"));
        coordinator.claim("action-1", "request-1");
        coordinator.markPendingVerification("action-1", 202, "op-1");

        var result = query.get("incident-1", "action-1");

        assertThat(result.state()).isEqualTo("PENDING_VERIFICATION");
        assertThat(result.operationId()).isEqualTo("op-1");
        assertThat(result.verificationAttempts()).isZero();
        assertThat(executions.findByActionProposalId("action-1").orElseThrow().getVerificationAttempts()).isZero();
    }

    @Test
    void doesNotExposeExecutionThroughAnotherIncident() {
        actions.saveAndFlush(action("action-2", "incident-1", "request-2"));
        coordinator.claim("action-2", "request-2");

        assertThatThrownBy(() -> query.get("incident-other", "action-2"))
            .isInstanceOf(IncidentNotFoundException.class);
    }

    private ActionProposalEntity action(String id, String incidentId, String requestId) {
        return new ActionProposalEntity(
            id,
            incidentId,
            requestId,
            "revoke-credential",
            "credential:test",
            "incident-remediation",
            "postman-echo.com",
            "[\"incident_id\",\"credential_id\",\"reason\"]",
            "[]",
            Instant.now()
        );
    }
}
