package br.com.t3privacyguard.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.persistence.AuditChainHeadRepository;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
class AuditIntegrityRotationTest {
    private static final String OLD_KEY = "old-audit-integrity-secret-123456789012345";
    private static final String NEW_KEY = "new-audit-integrity-secret-123456789012345";
    private static final String WRONG_KEY = "wrong-audit-integrity-secret-1234567890123";
    private static final String GATEWAY_KEY = "gateway-test-secret-123456789012345678901";
    private static final String REMEDIATION_KEY = "remediation-test-secret-12345678901234567";
    private static final String OPERATOR_PASSWORD = "operator-test-password-12345678901234567";

    @Autowired AuditEventRepository audits;
    @Autowired AuditChainHeadRepository heads;
    @Autowired IncidentRepository incidents;
    @Autowired PlatformTransactionManager transactionManager;

    private TransactionTemplate transactions;

    @BeforeEach
    void clear() {
        transactions = new TransactionTemplate(transactionManager);
        heads.deleteAll();
        audits.deleteAll();
        incidents.deleteAll();
    }

    @Test
    void rotatedKeyCanVerifyOldEventsAndAppendWithNewVersion() {
        String incidentId = incident();
        AuditIntegrityService oldService = service(OLD_KEY, "old", "");
        inTransaction(() -> oldService.append(incidentId, "INCIDENT_CREATED", "Created"));

        AuditIntegrityService rotatedService = service(NEW_KEY, "new", "old=" + OLD_KEY);
        assertThat(rotatedService.verify(incidentId).state()).isEqualTo(AuditIntegrityState.VERIFIED);

        inTransaction(() -> rotatedService.append(incidentId, "ACTION_PROPOSED", "Action proposed"));
        var verification = rotatedService.verify(incidentId);

        assertThat(verification.state()).isEqualTo(AuditIntegrityState.VERIFIED);
        assertThat(verification.eventsChecked()).isEqualTo(2);
        assertThat(verification.events().get(0).getIntegrityKeyId()).isEqualTo("old");
        assertThat(verification.events().get(1).getIntegrityKeyId()).isEqualTo("new");
        assertThat(heads.findById(incidentId).orElseThrow().getIntegrityKeyId()).isEqualTo("new");
    }

    @Test
    void restartWithWrongMaterialForSameKeyIdBreaksVerification() {
        String incidentId = incident();
        AuditIntegrityService original = service(OLD_KEY, "old", "");
        inTransaction(() -> original.append(incidentId, "INCIDENT_CREATED", "Created"));

        AuditIntegrityService wrongRestart = service(WRONG_KEY, "old", "");

        assertThat(wrongRestart.verify(incidentId).state()).isEqualTo(AuditIntegrityState.BROKEN);
    }

    @Test
    void currentAuditKeyCannotReuseOtherBackendSecrets() {
        assertThatThrownBy(() -> new AuditIntegrityKeyring(
            GATEWAY_KEY,
            "audit",
            "",
            GATEWAY_KEY,
            REMEDIATION_KEY,
            OPERATOR_PASSWORD
        )).isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("GATEWAY_SERVICE_TOKEN");
    }

    private AuditIntegrityService service(String key, String keyId, String previousKeys) {
        AuditIntegrityKeyring keyring = new AuditIntegrityKeyring(
            key,
            keyId,
            previousKeys,
            GATEWAY_KEY,
            REMEDIATION_KEY,
            OPERATOR_PASSWORD
        );
        return new AuditIntegrityService(incidents, audits, heads, keyring, false);
    }

    private String incident() {
        String id = UUID.randomUUID().toString();
        incidents.saveAndFlush(new IncidentEntity(
            id,
            "Synthetic",
            Severity.CRITICAL,
            "Synthetic incident",
            "test",
            Instant.now()
        ));
        return id;
    }

    private void inTransaction(Runnable operation) {
        transactions.executeWithoutResult(status -> operation.run());
    }
}
