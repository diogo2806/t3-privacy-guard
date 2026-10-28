package br.com.t3privacyguard.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.integration.PolicyAdministrationException.Kind;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The policy administration client against a stand-in guard-runtime answering /v1/policy. */
class RuntimePolicyAdminClientTest {
    private static final String PROPOSAL_TOKEN = "test-runtime-proposal-token-1234567890";
    private static final String EXECUTOR_TOKEN = "test-runtime-executor-token-1234567890";
    private static final String ADMIN_TOKEN = "test-runtime-policy-admin-token-1234567890";
    private static final String HASH = "a".repeat(64);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final List<JsonNode> bodies = new ArrayList<>();
    private final List<String> authorizations = new ArrayList<>();
    private HttpServer server;
    private int status = 200;
    private String answer = "{}";

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void readsTheCurrentPolicyWithThePolicyAdminToken() {
        answer = "{\"managed\":true,\"state\":\"AVAILABLE\",\"version\":\"v1\",\"hash\":\"" + HASH + "\",\"document\":{\"version\":\"v1\",\"actions\":{}}}";

        var view = client(ADMIN_TOKEN).current();

        assertThat(view.administrationConfigured()).isTrue();
        assertThat(view.managed()).isTrue();
        assertThat(view.version()).isEqualTo("v1");
        assertThat(view.document().path("version").asText()).isEqualTo("v1");
        assertThat(authorizations).containsExactly("Bearer " + ADMIN_TOKEN);
    }

    @Test
    void publishSendsTheExpectedHashAndTheRequester() {
        answer = "{\"changed\":true,\"version\":\"v2\",\"hash\":\"" + HASH + "\",\"previous_version\":\"v1\",\"previous_hash\":\"" + "b".repeat(64) + "\"}";

        var change = client(ADMIN_TOKEN).publish(MAPPER.createObjectNode().put("version", "v2"), "b".repeat(64), "alice smith");

        assertThat(change.changed()).isTrue();
        assertThat(change.previousVersion()).isEqualTo("v1");
        assertThat(bodies.get(0).path("expected_current_hash").asText()).isEqualTo("b".repeat(64));
        assertThat(bodies.get(0).path("requested_by").asText()).isEqualTo("alice_smith");
        assertThat(bodies.get(0).path("document").path("version").asText()).isEqualTo("v2");
    }

    @Test
    void mapsRuntimeRefusalsToTypedErrors() {
        RuntimePolicyAdminClient admin = client(ADMIN_TOKEN);
        var document = MAPPER.createObjectNode();

        status = 409;
        answer = "{\"error\":\"POLICY_CHANGED\",\"reason\":\"the current policy changed since it was read\"}";
        assertThatThrownBy(() -> admin.publish(document, HASH, "alice"))
            .isInstanceOfSatisfying(PolicyAdministrationException.class, ex -> assertThat(ex.kind()).isEqualTo(Kind.CONFLICT));

        status = 422;
        answer = "{\"error\":\"POLICY_INVALID\",\"reason\":\"policy attempts to allow a contract-forbidden secret field\"}";
        assertThatThrownBy(() -> admin.publish(document, HASH, "alice"))
            .isInstanceOfSatisfying(PolicyAdministrationException.class, ex -> {
                assertThat(ex.kind()).isEqualTo(Kind.INVALID);
                assertThat(ex.getMessage()).isEqualTo("policy attempts to allow a contract-forbidden secret field");
            });

        status = 409;
        answer = "{\"error\":\"POLICY_MANAGEMENT_DISABLED\"}";
        assertThatThrownBy(() -> admin.rollback("v1", HASH, "alice"))
            .isInstanceOfSatisfying(PolicyAdministrationException.class, ex -> assertThat(ex.kind()).isEqualTo(Kind.UNAVAILABLE));

        status = 403;
        answer = "{\"error\":\"FUNCTION_NOT_GRANTED\"}";
        assertThatThrownBy(admin::current)
            .isInstanceOfSatisfying(PolicyAdministrationException.class, ex -> assertThat(ex.code()).isEqualTo("POLICY_ADMIN_NOT_GRANTED"));

        status = 500;
        answer = "{}";
        assertThatThrownBy(() -> admin.history(10)).isInstanceOf(TrustRuntimeUnavailableException.class);
    }

    @Test
    void withoutTheAdminTokenPolicyIsReadOnlyAndNothingIsSent() {
        RuntimePolicyAdminClient admin = client("");

        assertThat(admin.current().administrationConfigured()).isFalse();
        assertThatThrownBy(() -> admin.publish(MAPPER.createObjectNode(), null, "alice"))
            .isInstanceOfSatisfying(PolicyAdministrationException.class, ex -> assertThat(ex.code()).isEqualTo("POLICY_ADMIN_NOT_CONFIGURED"));
        assertThat(authorizations).isEmpty();
    }

    @Test
    void theAdminTokenMustBeDistinct() {
        assertThatThrownBy(() -> new GuardRuntimeClient(MAPPER, "http://runtime:3101", "agent:proposal", PROPOSAL_TOKEN,
            "agent:executor", EXECUTOR_TOKEN, PROPOSAL_TOKEN, 2_000))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("GUARD_RUNTIME_POLICY_ADMIN_TOKEN");
    }

    @Test
    void requesterNamesAreReducedToTheRuntimeAlphabet() {
        assertThat(RuntimePolicyAdminClient.requestedBy("ana.souza@example.com")).isEqualTo("ana.souza@example.com");
        assertThat(RuntimePolicyAdminClient.requestedBy("-admin")).isEqualTo("u-admin");
        assertThat(RuntimePolicyAdminClient.requestedBy("x".repeat(200))).hasSize(128);
        assertThat(RuntimePolicyAdminClient.requestedBy(" ")).isNull();
    }

    private RuntimePolicyAdminClient client(String adminToken) {
        GuardRuntimeClient runtime = new GuardRuntimeClient(MAPPER, "http://127.0.0.1:" + server.getAddress().getPort(),
            "agent:proposal", PROPOSAL_TOKEN, "agent:executor", EXECUTOR_TOKEN, adminToken, 2_000);
        return new RuntimePolicyAdminClient(runtime);
    }

    private void handle(HttpExchange exchange) throws IOException {
        authorizations.add(exchange.getRequestHeaders().getFirst("Authorization"));
        byte[] body = exchange.getRequestBody().readAllBytes();
        if (body.length > 0) bodies.add(MAPPER.readTree(body));
        byte[] response = answer.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }
}
