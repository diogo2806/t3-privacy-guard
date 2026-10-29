package br.com.t3privacyguard.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;

/** The app reaching guard-runtime over mutual TLS: a stand-in runtime that requires a client certificate from our CA. */
class GuardRuntimeTlsTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String PROPOSAL_TOKEN = "test-runtime-proposal-token-1234567890";
    private static final String EXECUTOR_TOKEN = "test-runtime-executor-token-1234567890";

    private HttpsServer server;

    @BeforeEach
    void start() throws Exception {
        SSLContext context = SslBundle.of(new PemSslStoreBundle(
            PemSslStoreDetails.forCertificate("classpath:tls/server.crt").withPrivateKey("classpath:tls/server.key"),
            PemSslStoreDetails.forCertificate("classpath:tls/ca.crt"))).createSslContext();
        server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters parameters = context.getDefaultSSLParameters();
                parameters.setNeedClientAuth(true);
                params.setSSLParameters(parameters);
            }
        });
        server.createContext("/", exchange -> {
            byte[] body = "{\"status\":\"UP\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void connectsWithTheAppsClientCertificate() {
        GuardRuntimeClient runtime = client("https://localhost:" + server.getAddress().getPort(), "classpath:tls/ca.crt", "classpath:tls/client.crt", "classpath:tls/client.key");
        assertThat(runtime.getPublic("/actuator/health").ok()).isTrue();
    }

    @Test
    void failsClosedWithoutAClientCertificate() {
        GuardRuntimeClient runtime = client("https://localhost:" + server.getAddress().getPort(), "classpath:tls/ca.crt", "", "");
        assertThatThrownBy(() -> runtime.getPublic("/actuator/health")).isInstanceOf(TrustRuntimeUnavailableException.class);
    }

    @Test
    void rejectsInconsistentTlsSettings() {
        assertThatThrownBy(() -> client("http://runtime:3101", "classpath:tls/ca.crt", "", "")).hasMessageContaining("https://");
        assertThatThrownBy(() -> client("https://runtime:3101", "", "classpath:tls/client.crt", "")).hasMessageContaining("go together");
        assertThatThrownBy(() -> client("https://runtime:3101", "classpath:tls/missing.crt", "", "")).hasMessageContaining("could not be loaded");
    }

    private static GuardRuntimeClient client(String url, String ca, String certificate, String key) {
        return new GuardRuntimeClient(MAPPER, url, "agent:proposal", PROPOSAL_TOKEN, "agent:executor", EXECUTOR_TOKEN, "", ca, certificate, key, 2_000);
    }
}
