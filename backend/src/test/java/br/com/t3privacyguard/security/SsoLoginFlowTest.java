package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The whole OpenID Connect sign-in against a stand-in identity provider (discovery, signed ID token, JWKS): the
 * dashboard's link starts it, the provider's groups become Privacy Guard roles, and an account without a mapped group
 * is refused. Local sign-in is switched off here, as in an SSO-only deployment.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SsoLoginFlowTest {
    private static final String CLIENT_ID = "privacy-guard-test";
    private static RSAKey signingKey;
    private static HttpServer provider;
    private static String issuer;
    private static volatile String nonce;
    private static volatile List<String> groups = List.of();

    @Autowired MockMvc mvc;

    @DynamicPropertySource
    static void sso(DynamicPropertyRegistry registry) throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("test-key").generate();
        provider = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        provider.createContext("/", SsoLoginFlowTest::handle);
        provider.start();
        issuer = "http://127.0.0.1:" + provider.getAddress().getPort();
        registry.add("privacy-guard.sso.issuer-uri", () -> issuer);
        registry.add("privacy-guard.sso.client-id", () -> CLIENT_ID);
        registry.add("privacy-guard.sso.client-secret", () -> "test-sso-client-secret-1234567890");
        registry.add("privacy-guard.sso.role-mapping", () -> "{\"APPROVER\":[\"soc-approvers\"],\"AUDITOR\":[\"auditors\"]}");
        registry.add("privacy-guard.sso.local-login-enabled", () -> "false");
    }

    @AfterAll
    static void stop() {
        provider.stop(0);
    }

    @Test
    void providerGroupsBecomeRolesAndTheSessionIsEstablished() throws Exception {
        groups = List.of("soc-approvers", "everyone");
        MockHttpSession session = signIn();

        mvc.perform(get("/api/auth/session").session(session))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.authenticated").value(true))
            .andExpect(jsonPath("$.username").value("ana@example.com"))
            .andExpect(jsonPath("$.authorities[0]").value("APPROVER"))
            .andExpect(jsonPath("$.authorities.length()").value(1))
            .andExpect(jsonPath("$.ssoEnabled").value(true))
            .andExpect(jsonPath("$.localLoginEnabled").value(false));
        mvc.perform(get("/api/incidents").session(session)).andExpect(status().isOk());
    }

    @Test
    void anAccountWithoutAMappedGroupIsRefused() throws Exception {
        groups = List.of("everyone");
        MvcResult start = mvc.perform(get("/oauth2/authorization/sso")).andExpect(status().is3xxRedirection()).andReturn();
        MockHttpSession session = (MockHttpSession) start.getRequest().getSession();
        Map<String, String> query = query(start.getResponse().getRedirectedUrl());
        nonce = query.get("nonce");

        mvc.perform(get("/login/oauth2/code/sso").session(session).param("code", "code-2").param("state", query.get("state")))
            .andExpect(redirectedUrl("/?sso=error"));
        mvc.perform(get("/api/auth/session").session(session)).andExpect(jsonPath("$.authenticated").value(false));
    }

    @Test
    void localSignInIsOffInAnSsoOnlyDeployment() throws Exception {
        mvc.perform(post("/api/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"operator\",\"password\":\"whatever-password\"}"))
            .andExpect(status().isForbidden());
    }

    private MockHttpSession signIn() throws Exception {
        MvcResult start = mvc.perform(get("/oauth2/authorization/sso")).andExpect(status().is3xxRedirection()).andReturn();
        String authorize = start.getResponse().getRedirectedUrl();
        assertThat(authorize).startsWith(issuer + "/authorize").contains("client_id=" + CLIENT_ID).contains("scope=openid");
        MockHttpSession session = (MockHttpSession) start.getRequest().getSession();
        Map<String, String> query = query(authorize);
        nonce = query.get("nonce");

        MvcResult callback = mvc.perform(get("/login/oauth2/code/sso").session(session).param("code", "code-1").param("state", query.get("state")))
            .andExpect(redirectedUrl("/"))
            .andReturn();
        // Session fixation protection replaces the pre-login session at sign-in.
        return (MockHttpSession) callback.getRequest().getSession(false);
    }

    private static Map<String, String> query(String url) {
        Map<String, String> values = new HashMap<>();
        for (String pair : URI.create(url).getRawQuery().split("&")) {
            String[] parts = pair.split("=", 2);
            values.put(parts[0], parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "");
        }
        return values;
    }

    private static void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String body;
        try {
            body = switch (path) {
                case "/.well-known/openid-configuration" -> """
                    {"issuer":"%1$s","authorization_endpoint":"%1$s/authorize","token_endpoint":"%1$s/token","jwks_uri":"%1$s/jwks",
                     "response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],
                     "scopes_supported":["openid","profile","email"]}""".formatted(issuer);
                case "/jwks" -> new JWKSet(signingKey.toPublicJWK()).toString();
                case "/token" -> "{\"access_token\":\"access-1\",\"token_type\":\"Bearer\",\"expires_in\":300,\"id_token\":\"" + idToken() + "\"}";
                default -> null;
            };
        } catch (Exception ex) {
            body = null;
        }
        byte[] bytes = (body == null ? "{}" : body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(body == null ? 404 : 200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static String idToken() throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("user-123")
            .audience(CLIENT_ID)
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(300)))
            .claim("nonce", nonce)
            .claim("preferred_username", "ana@example.com")
            .claim("groups", groups)
            .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(signingKey));
        return jwt.serialize();
    }
}
