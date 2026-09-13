package br.com.t3privacyguard.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class TrustedNormalPayloadFactoryTest {
    private final TrustedNormalPayloadFactory factory = new TrustedNormalPayloadFactory();

    @Test
    void createsOnlyServerOwnedSyntheticValuesForRequestedSafeFields() {
        var payload = factory.create(List.of("incident_id", "credential_id", "reason", "employee_department"));

        assertThat(payload).containsEntry("incident_id", "inc-demo-001")
            .containsEntry("credential_id", "cred-demo-001")
            .containsEntry("reason", "suspected compromise")
            .containsEntry("employee_department", "finance");
    }

    @Test
    void never_materializes_secret_or_unknown_field_values() {
        var payload = factory.create(List.of("api_key", "password", "unknown_field", "reason"));

        assertThat(payload).containsOnlyKeys("reason");
        assertThat(payload).doesNotContainKeys("api_key", "password", "unknown_field");
    }

    @Test
    void canonicalizesNamesWithoutAllowingClientSuppliedValues() {
        var payload = factory.create(List.of(" Reason ", "INCIDENT_ID"));

        assertThat(payload).containsEntry("reason", "suspected compromise")
            .containsEntry("incident_id", "inc-demo-001");
    }
}
