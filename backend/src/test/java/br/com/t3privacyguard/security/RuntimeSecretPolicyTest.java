package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.audit.AuditIntegrityKeyring;
import org.junit.jupiter.api.Test;

class RuntimeSecretPolicyTest {
    @Test
    void rejectsDocumentedOperatorUsernameBeforeCreatingPrincipal() {
        SecurityConfig config = new SecurityConfig();

        assertThatThrownBy(() -> config.operatorUserDetailsService(
            "replace-with-operator-username",
            "runtime-operator-password",
            config.passwordEncoder()
        ))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("OPERATOR_USERNAME must be replaced with a runtime-specific value");
    }

    @Test
    void rejectsDocumentedOperatorPasswordBeforeCreatingPrincipal() {
        SecurityConfig config = new SecurityConfig();

        assertThatThrownBy(() -> config.operatorUserDetailsService(
            "runtime-operator",
            "replace-with-strong-operator-password",
            config.passwordEncoder()
        ))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("OPERATOR_PASSWORD must be replaced with a runtime-specific value");
    }

    @Test
    void acceptsRuntimeSpecificOperatorCredentials() {
        SecurityConfig config = new SecurityConfig();
        var users = config.operatorUserDetailsService(
            "runtime-operator",
            "runtime-operator-password",
            config.passwordEncoder()
        );

        assertThat(users.loadUserByUsername("runtime-operator").getUsername()).isEqualTo("runtime-operator");
    }

    @Test
    void rejectsDocumentedAuditIntegrityKey() {
        assertThatThrownBy(() -> new AuditIntegrityKeyring(
            "replace-with-distinct-at-least-32-random-characters",
            "primary",
            "",
            "gateway-runtime-token-12345678901234567890",
            "runtime-remediation-private-key",
            "runtime-operator-password"
        ))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("AUDIT_INTEGRITY_KEY must be replaced with a runtime-specific value");
    }

    @Test
    void acceptsDistinctRuntimeAuditIntegrityKey() {
        AuditIntegrityKeyring keyring = new AuditIntegrityKeyring(
            "audit-runtime-key-123456789012345678901234567890",
            "primary",
            "",
            "gateway-runtime-token-12345678901234567890",
            "runtime-remediation-private-key",
            "runtime-operator-password"
        );

        assertThat(keyring.currentKeyId()).isEqualTo("primary");
    }
}
