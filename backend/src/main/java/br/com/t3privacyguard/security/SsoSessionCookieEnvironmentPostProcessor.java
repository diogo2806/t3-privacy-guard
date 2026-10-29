package br.com.t3privacyguard.security;

import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

/**
 * With single sign-on the identity provider sends the browser back through a cross-site redirect, which a
 * SameSite=Strict session cookie would not accompany, losing the sign-in state. Lax still keeps the cookie off
 * cross-site POSTs, and every state change also needs the CSRF token. An explicit SESSION_COOKIE_SAME_SITE wins.
 */
public class SsoSessionCookieEnvironmentPostProcessor implements EnvironmentPostProcessor {
    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        String issuer = environment.getProperty("privacy-guard.sso.issuer-uri", "");
        if (issuer.isBlank() || environment.containsProperty("SESSION_COOKIE_SAME_SITE")) return;
        environment.getPropertySources().addFirst(new MapPropertySource("privacy-guard-sso-session-cookie",
            Map.of("server.servlet.session.cookie.same-site", "lax")));
    }
}
