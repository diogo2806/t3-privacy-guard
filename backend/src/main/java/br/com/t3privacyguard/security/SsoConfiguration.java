package br.com.t3privacyguard.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * OpenID Connect single sign-on, on only when OIDC_ISSUER_URI is set. The provider is discovered from the issuer at
 * startup, so a wrong issuer stops the app instead of failing at the first sign-in.
 */
@Configuration
public class SsoConfiguration {
    public static final String REGISTRATION_ID = "sso";
    static final String ENABLED = "!'${privacy-guard.sso.issuer-uri:}'.isBlank()";

    @Bean
    @ConditionalOnExpression(ENABLED)
    ClientRegistrationRepository ssoClientRegistrations(
        @Value("${privacy-guard.sso.issuer-uri}") String issuerUri,
        @Value("${privacy-guard.sso.client-id:}") String clientId,
        @Value("${privacy-guard.sso.client-secret:}") String clientSecret,
        @Value("${privacy-guard.sso.scopes:openid,profile,email}") String scopes,
        @Value("${privacy-guard.sso.username-claim:preferred_username}") String usernameClaim
    ) {
        if (clientId.isBlank() || clientSecret.isBlank()) throw new IllegalStateException("OIDC_CLIENT_ID and OIDC_CLIENT_SECRET are required for single sign-on");
        RuntimeSecretPolicy.rejectDocumentationPlaceholder(clientSecret, "OIDC_CLIENT_SECRET");
        ClientRegistration registration = ClientRegistrations.fromIssuerLocation(issuerUri.trim())
            .registrationId(REGISTRATION_ID)
            .clientId(clientId.trim())
            .clientSecret(clientSecret.trim())
            .scope(Arrays.stream(scopes.split("[\\s,]+")).filter(scope -> !scope.isBlank()).toList())
            .userNameAttributeName(usernameClaim.trim())
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .build();
        return new InMemoryClientRegistrationRepository(registration);
    }

    @Bean
    @ConditionalOnExpression(ENABLED)
    SsoRoleMapper ssoRoleMapper(
        @Value("${privacy-guard.sso.roles-claim:groups}") String rolesClaim,
        @Value("${privacy-guard.sso.role-mapping:{}}") String roleMapping,
        ObjectMapper mapper
    ) {
        return new SsoRoleMapper(rolesClaim, roleMapping, mapper);
    }

    /** The provider authenticates; Privacy Guard decides the roles, and an account without one is refused. */
    static OAuth2UserService<OidcUserRequest, OidcUser> userService(SsoRoleMapper roles) {
        OidcUserService delegate = new OidcUserService();
        return request -> {
            OidcUser user = delegate.loadUser(request);
            var authorities = roles.authorities(user.getClaims());
            if (authorities.isEmpty()) {
                throw new OAuth2AuthenticationException(new OAuth2Error("access_denied", "This account has no Privacy Guard role", null));
            }
            String usernameClaim = request.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
            if (!(user.getClaims().get(usernameClaim) instanceof String name) || name.isBlank()) {
                throw new OAuth2AuthenticationException(new OAuth2Error("invalid_user", "The identity provider did not send " + usernameClaim, null));
            }
            return new DefaultOidcUser(authorities, user.getIdToken(), user.getUserInfo(), usernameClaim);
        };
    }
}
