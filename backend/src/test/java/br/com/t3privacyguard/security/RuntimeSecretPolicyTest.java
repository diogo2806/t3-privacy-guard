package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.audit.AuditIntegrityKeyring;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UserDetailsService;

class RuntimeSecretPolicyTest {
    @Test
    void rejectsDocumentedOperatorUsernameBeforeCreatingPrincipal() {
        SecurityConfig config = new SecurityConfig();

        assertThatThrownBy(() -> localUsers(config, "replace-with-operator-username", "runtime-operator-password"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("OPERATOR_USERNAME must be replaced with a runtime-specific value");
    }

    @Test
    void rejectsDocumentedOperatorPasswordBeforeCreatingPrincipal() {
        SecurityConfig config = new SecurityConfig();

        assertThatThrownBy(() -> localUsers(config, "runtime-operator", "replace-with-strong-operator-password"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("OPERATOR_PASSWORD must be replaced with a runtime-specific value");
    }

    @Test
    void acceptsRuntimeSpecificOperatorCredentialsWithAllLocalSemanticAuthorities() {
        SecurityConfig config = new SecurityConfig();
        var users = localUsers(config, "runtime-operator", "runtime-operator-password");
        var user = users.loadUserByUsername("runtime-operator");

        assertThat(user.getUsername()).isEqualTo("runtime-operator");
        assertThat(user.getAuthorities()).extracting("authority")
            .containsExactlyInAnyOrder("ROLE_ANALYST", "ROLE_APPROVER", "ROLE_EXECUTOR", "ROLE_AUDITOR");
    }

    @Test
    void enterpriseModeRequiresDistinctHumanPrincipals() {
        SecurityConfig config = new SecurityConfig();

        assertThatThrownBy(() -> config.operatorUserDetailsService(
            true,
            "",
            "",
            "shared-human",
            "analyst-password",
            "shared-human",
            "approver-password",
            "executor-01",
            "executor-password",
            "auditor-01",
            "auditor-password",
            config.passwordEncoder()
        ))
            .isInstanceOf(IllegalStateException.class)
            .hasMessage("Enterprise separation of duties requires four distinct human principals");
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

    private static UserDetailsService localUsers(SecurityConfig config, String username, String password) {
        return config.operatorUserDetailsService(
            false,
            username,
            password,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            config.passwordEncoder()
        );
    }
}
