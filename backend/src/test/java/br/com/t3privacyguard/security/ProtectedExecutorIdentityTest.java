package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ProtectedExecutorIdentityTest {
    @Test
    void acceptsT3nDidsAndSelfHostedCallerIds() {
        assertThat(ProtectedExecutorIdentity.isValid("agent:protected-executor")).isTrue();
        assertThat(ProtectedExecutorIdentity.isValid("agent:executor")).isTrue();
    }

    @Test
    void rejectsMissingOrUnsafeIdentities() {
        assertThat(ProtectedExecutorIdentity.isValid(null)).isFalse();
        assertThat(ProtectedExecutorIdentity.isValid("")).isFalse();
        assertThat(ProtectedExecutorIdentity.isValid("agent executor")).isFalse();
        assertThat(ProtectedExecutorIdentity.isValid(":executor")).isFalse();
        assertThat(ProtectedExecutorIdentity.isValid("agent/executor")).isFalse();
        assertThat(ProtectedExecutorIdentity.isValid("a".repeat(129))).isFalse();
    }
}
