package br.com.privacyguard.runtime.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.pem.PemSslStoreBundle;
import org.springframework.boot.ssl.pem.PemSslStoreDetails;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** With TLS and client authentication on, only a client certificate signed by the configured CA gets a connection. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class MutualTlsTest {
    private static final Path WORK = workDirectory();

    @LocalServerPort
    int port;

    @DynamicPropertySource
    static void runtimeProperties(DynamicPropertyRegistry registry) {
        registry.add("guard-runtime.policy-file", () -> WORK.resolve("current.json").toString());
        registry.add("guard-runtime.replay-file", () -> WORK.resolve("replay.json").toString());
        registry.add("guard-runtime.activity-file", () -> WORK.resolve("activity.jsonl").toString());
        registry.add("guard-runtime.callers-json", () ->
            "[{\"id\":\"agent:proposal\",\"token\":\"test-proposal-agent-token-0123456789abcdef\",\"functions\":[\"evaluate-action\"]}]");
        registry.add("server.ssl.enabled", () -> "true");
        registry.add("server.ssl.certificate", () -> "classpath:tls/server.crt");
        registry.add("server.ssl.certificate-private-key", () -> "classpath:tls/server.key");
        registry.add("server.ssl.trust-certificate", () -> "classpath:tls/ca.crt");
        registry.add("server.ssl.client-auth", () -> "need");
    }

    @Test
    void acceptsTheAppsClientCertificate() throws Exception {
        HttpResponse<String> response = client("classpath:tls/client.crt", "classpath:tls/client.key").send(health(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
    }

    @Test
    void refusesAClientWithoutACertificateOrWithAnUntrustedOne() {
        assertThatThrownBy(() -> client(null, null).send(health(), HttpResponse.BodyHandlers.ofString())).isInstanceOf(IOException.class);
        assertThatThrownBy(() -> client("classpath:tls/rogue.crt", "classpath:tls/rogue.key").send(health(), HttpResponse.BodyHandlers.ofString()))
            .isInstanceOf(IOException.class);
    }

    private HttpRequest health() {
        return HttpRequest.newBuilder(URI.create("https://localhost:" + port + "/actuator/health")).GET().build();
    }

    private static HttpClient client(String certificate, String privateKey) {
        PemSslStoreDetails key = certificate == null ? null : PemSslStoreDetails.forCertificate(certificate).withPrivateKey(privateKey);
        SSLContext context = SslBundle.of(new PemSslStoreBundle(key, PemSslStoreDetails.forCertificate("classpath:tls/ca.crt"))).createSslContext();
        return HttpClient.newBuilder().sslContext(context).build();
    }

    private static Path workDirectory() {
        try {
            Path directory = Files.createTempDirectory("guard-runtime-tls");
            directory.toFile().deleteOnExit();
            Files.copy(Path.of("policy/privacy-guard-policy.json"), directory.resolve("current.json"));
            return directory;
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
