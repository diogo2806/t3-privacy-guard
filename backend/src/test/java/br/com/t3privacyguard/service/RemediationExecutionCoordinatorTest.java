package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class RemediationExecutionCoordinatorTest {
    @Autowired RemediationExecutionCoordinator coordinator;
    @Autowired ActionProposalRepository actions;
    @Autowired RemediationExecutionRepository executions;

    @BeforeEach
    void clear() {
        executions.deleteAll();
        actions.deleteAll();
    }

    @Test
    void freshInFlightClaimIsNotMisclassifiedAsRecoveryFailure() {
        actions.saveAndFlush(new ActionProposalEntity(
            "action-1",
            "incident-1",
            "request-1",
            "revoke-credential",
            "credential:test",
            "incident-remediation",
            "postman-echo.com",
            "[\"incident_id\",\"credential_id\",\"reason\"]",
            "[]",
            Instant.now()
        ));

        var claim = coordinator.claim("action-1", "request-1");
        assertThat(claim.acquired()).isTrue();

        var observed = coordinator.markUnverified("action-1", "RECOVERY_EXECUTION_OUTCOME_UNKNOWN");

        assertThat(observed.getStatus().name()).isEqualTo("EXECUTING");
        assertThat(observed.getFailureCode()).isNull();
    }
}
