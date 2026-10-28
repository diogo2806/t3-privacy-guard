package br.com.t3privacyguard.integration;

import static org.assertj.core.api.Assertions.assertThat;

import br.com.t3privacyguard.integration.RuntimeStatusClient.DelegationStatus;
import org.junit.jupiter.api.Test;

class DelegationStatusTest {
    @Test
    void malformedDelegationStatusNormalizesToUnknownAndEmptyLists() {
        DelegationStatus malformed = new DelegationStatus("BOGUS", "INCOMPLETE", null, null, null, null, null);
        assertThat(malformed.memberState()).isEqualTo("UNKNOWN");
        assertThat(malformed.effectiveState()).isEqualTo("UNKNOWN");
        assertThat(malformed.functions()).isEmpty();
        assertThat(malformed.checkedFunctions()).isEmpty();
    }
}
