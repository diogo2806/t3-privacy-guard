package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class SecurityRemediationCredentialTest {
    private static final String KEY = "0123456789abcdef0123456789abcdef0123456789abcdef";

    @Test
    void blankCredentialIsFailClosedAndReportedAsNotConfigured() {
        var credential = new SecurityRemediationCredential("   ");

        assertThat(credential.isConfigured()).isFalse();
        assertThat(credential.matches(KEY)).isFalse();
    }

    @Test
    void configuredCredentialMatchesOnlyExactBearerValue() {
        var credential = new SecurityRemediationCredential(KEY);

        assertThat(credential.isConfigured()).isTrue();
        assertThat(credential.matches(KEY)).isTrue();
        assertThat(credential.matches(KEY + "x")).isFalse();
        assertThat(credential.matches("x".repeat(KEY.length()))).isFalse();
    }

    @Test
    void rejectsShortOrDocumentationPlaceholderCredentials() {
        assertThatThrownBy(() -> new SecurityRemediationCredential("too-short"))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("32 and 512");

        assertThatThrownBy(() -> new SecurityRemediationCredential("replace-with-security-api-key-1234567890"))
            .isInstanceOf(IllegalStateException.class);
    }
}
