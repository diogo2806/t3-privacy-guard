package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import org.junit.jupiter.api.Test;

class NormalPayloadCanonicalizerTest {
    @Test
    void canonicalHashMatchesCrossRuntimeVector() {
        Map<String, String> payload = Map.of(
            "incident_id", "inc-demo-001",
            "credential_id", "cred-demo-001",
            "reason", "suspected compromise"
        );

        assertThat(NormalPayloadCanonicalizer.canonical(payload)).isEqualTo(
            "13:credential_id=13:cred-demo-001\n"
                + "11:incident_id=12:inc-demo-001\n"
                + "6:reason=20:suspected compromise\n"
        );
        assertThat(NormalPayloadCanonicalizer.sha256(payload))
            .isEqualTo("39ba6c4944b8e22ae8bb5bb1ebc7d98839593f17d51acd5d5aff31c81ebaa8ae");
    }

    @Test
    void rejectsInvalidKeysAndOversizedValues() {
        assertThatThrownBy(() -> NormalPayloadCanonicalizer.sha256(Map.of("Api-Key", "x")))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> NormalPayloadCanonicalizer.sha256(Map.of("reason", "x".repeat(513))))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
