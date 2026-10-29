package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.GrantedAuthority;

class SsoRoleMapperTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void grantsOnlyTheMappedRoles() {
        SsoRoleMapper mapper = new SsoRoleMapper("groups", "{\"ANALYST\":[\"soc-analysts\"],\"AUDITOR\":[\"auditors\",\"risk\"]}", MAPPER);

        assertThat(roles(mapper, Map.of("groups", List.of("soc-analysts", "risk", "everyone")))).containsExactly("ROLE_ANALYST", "ROLE_AUDITOR");
        assertThat(roles(mapper, Map.of("groups", List.of("everyone")))).isEmpty();
        assertThat(roles(mapper, Map.of())).isEmpty();
    }

    @Test
    void readsNestedClaimsAndSpaceSeparatedStrings() {
        SsoRoleMapper keycloak = new SsoRoleMapper("realm_access.roles", "{\"POLICY_ADMIN\":[\"privacy-admin\"]}", MAPPER);
        assertThat(roles(keycloak, Map.of("realm_access", Map.of("roles", List.of("privacy-admin"))))).containsExactly("ROLE_POLICY_ADMIN");

        SsoRoleMapper scopes = new SsoRoleMapper("roles", "{\"EXECUTOR\":[\"remediation.execute\"]}", MAPPER);
        assertThat(roles(scopes, Map.of("roles", "openid remediation.execute"))).containsExactly("ROLE_EXECUTOR");
    }

    @Test
    void rejectsMappingsThatCannotWork() {
        assertThatThrownBy(() -> new SsoRoleMapper("groups", "{}", MAPPER)).hasMessageContaining("at least one role");
        assertThatThrownBy(() -> new SsoRoleMapper("groups", "{\"ADMIN\":[\"x\"]}", MAPPER)).hasMessageContaining("unknown role");
        assertThatThrownBy(() -> new SsoRoleMapper("groups", "{\"ANALYST\":[]}", MAPPER)).hasMessageContaining("at least one claim value");
        assertThatThrownBy(() -> new SsoRoleMapper("groups", "not json", MAPPER)).hasMessageContaining("JSON object");
    }

    @Test
    void ssoMakesTheSessionCookieLaxUnlessConfigured() {
        MockEnvironment withSso = new MockEnvironment().withProperty("privacy-guard.sso.issuer-uri", "https://login.example.com");
        new SsoSessionCookieEnvironmentPostProcessor().postProcessEnvironment(withSso, null);
        assertThat(withSso.getProperty("server.servlet.session.cookie.same-site")).isEqualTo("lax");

        MockEnvironment explicit = new MockEnvironment()
            .withProperty("privacy-guard.sso.issuer-uri", "https://login.example.com")
            .withProperty("SESSION_COOKIE_SAME_SITE", "strict")
            .withProperty("server.servlet.session.cookie.same-site", "strict");
        new SsoSessionCookieEnvironmentPostProcessor().postProcessEnvironment(explicit, null);
        assertThat(explicit.getProperty("server.servlet.session.cookie.same-site")).isEqualTo("strict");

        StandardEnvironment withoutSso = new StandardEnvironment();
        new SsoSessionCookieEnvironmentPostProcessor().postProcessEnvironment(withoutSso, null);
        assertThat(withoutSso.getPropertySources().contains("privacy-guard-sso-session-cookie")).isFalse();
    }

    private static List<String> roles(SsoRoleMapper mapper, Map<String, Object> claims) {
        return mapper.authorities(claims).stream().map(GrantedAuthority::getAuthority).toList();
    }
}
