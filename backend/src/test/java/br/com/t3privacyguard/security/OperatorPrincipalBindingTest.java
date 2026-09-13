package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class OperatorPrincipalBindingTest {
    @Test
    void canonicalizesAuthenticatedPrincipalAndProducesStableHash() {
        assertThat(OperatorPrincipalBinding.canonicalize("  ops-reviewer  ")).isEqualTo("ops-reviewer");
        assertThat(OperatorPrincipalBinding.canonicalize("ｏｐｓ-reviewer")).isEqualTo("ops-reviewer");
        assertThat(OperatorPrincipalBinding.sha256("ops-reviewer"))
            .isEqualTo("148e9dac7d995afa5849e431763e55c22e3795dfbc551ccb684d4872f8f35246");
    }

    @Test
    void rejectsAnonymousBlankControlAndOversizedPrincipals() {
        assertThatThrownBy(() -> OperatorPrincipalBinding.canonicalize(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OperatorPrincipalBinding.canonicalize(" ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OperatorPrincipalBinding.canonicalize("anonymousUser")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OperatorPrincipalBinding.canonicalize("ops\nreviewer")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OperatorPrincipalBinding.canonicalize("x".repeat(121))).isInstanceOf(IllegalArgumentException.class);
    }
}
