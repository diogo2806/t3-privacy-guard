package br.com.privacyguard.runtime.egress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.privacyguard.runtime.remediation.RemediationRules;
import br.com.privacyguard.runtime.store.ConfiguredPrivateProfileStore;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The only place the private value exists: resolved into the JSON string value right before sending. */
class HttpProtectedEgressTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final List<String> receivedBodies = new ArrayList<>();
    private final List<String> receivedAuthorization = new ArrayList<>();
    private HttpServer server;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/execute", exchange -> {
            receivedBodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            receivedAuthorization.add(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] body = "{\"operation_id\":\"op-1\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(202, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().add("Location", "/execute");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private String url(String path) {
        return "http://127.0.0.1:" + server.getAddress().getPort() + path;
    }

    private static HttpProtectedEgress egress(String verifiedEmail) {
        return new HttpProtectedEgress(new ConfiguredPrivateProfileStore(verifiedEmail), MAPPER, 5_000);
    }

    private static TreeMap<String, String> notificationBody() {
        return new TreeMap<>(Map.of("request_id", "r2", "action", "notify-security", "recipient", RemediationRules.VERIFIED_EMAIL_MARKER));
    }

    @Test
    void resolvesThePlaceholderOnlyInTheBytesSentUpstream() throws Exception {
        ProtectedEgress.Response response = egress("soc@example.test").post(url("/execute"), Map.of("Authorization", "Bearer key-123"), notificationBody());

        assertThat(response.code()).isEqualTo(202);
        assertThat(receivedAuthorization).containsExactly("Bearer key-123");
        JsonNode sent = MAPPER.readTree(receivedBodies.get(0));
        assertThat(sent.get("recipient").asText()).isEqualTo("soc@example.test");
        assertThat(receivedBodies.get(0)).doesNotContain("{{");
    }

    @Test
    void aPrivateValueCannotChangeTheJsonStructure() throws Exception {
        egress("x\",\"action\":\"delete-everything").post(url("/execute"), Map.of(), notificationBody());
        JsonNode sent = MAPPER.readTree(receivedBodies.get(0));
        assertThat(sent.get("action").asText()).isEqualTo("notify-security");
        assertThat(sent.get("recipient").asText()).isEqualTo("x\",\"action\":\"delete-everything");
    }

    @Test
    void unresolvedPlaceholderFailsBeforeAnyRequest() {
        assertThatThrownBy(() -> egress("").post(url("/execute"), Map.of(), notificationBody()))
            .isInstanceOf(EgressException.class)
            .extracting(error -> ((EgressException) error).kind()).isEqualTo(EgressException.Kind.PLACEHOLDER_UNKNOWN);
        TreeMap<String, String> other = new TreeMap<>(Map.of("note", "{{profile.home_address}}"));
        assertThatThrownBy(() -> egress("soc@example.test").post(url("/execute"), Map.of(), other)).isInstanceOf(EgressException.class);
        assertThat(receivedBodies).isEmpty();
    }

    @Test
    void redirectsAreNotFollowed() {
        ProtectedEgress.Response response = egress("soc@example.test").post(url("/redirect"), Map.of(), notificationBody());
        assertThat(response.code()).isEqualTo(302);
        assertThat(receivedBodies).isEmpty();
    }

    @Test
    void unreachableUpstreamIsAnUpstreamError() {
        String closed = url("/execute");
        server.stop(0);
        assertThatThrownBy(() -> egress("soc@example.test").post(closed, Map.of(), notificationBody()))
            .isInstanceOf(EgressException.class)
            .extracting(error -> ((EgressException) error).kind()).isEqualTo(EgressException.Kind.UPSTREAM_ERROR);
    }
}
