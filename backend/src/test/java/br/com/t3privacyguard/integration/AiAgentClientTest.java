package br.com.t3privacyguard.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.privacy.IncidentDataMinimizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AiAgentClientTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final List<JsonNode> requests = new ArrayList<>();
    private final AtomicReference<String> toolArguments = new AtomicReference<>();
    private HttpServer provider;

    @BeforeEach
    void start() throws Exception {
        provider = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        provider.createContext("/v1/chat/completions", exchange -> {
            requests.add(MAPPER.readTree(exchange.getRequestBody().readAllBytes()));
            String body = """
                {"choices":[{"message":{"tool_calls":[{"function":{"name":"propose_privacy_guard_action","arguments":%s}}]}}]}"""
                .formatted(MAPPER.writeValueAsString(toolArguments.get()));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        provider.start();
    }

    @AfterEach
    void stop() {
        provider.stop(0);
    }

    private AiAgentClient client() {
        return new AiAgentClient(new IncidentDataMinimizer(), MAPPER, "openai-compatible",
            "http://127.0.0.1:" + provider.getAddress().getPort() + "/v1/chat/completions", "provider-test-key", "test-model", false);
    }

    @Test
    void returnsAValidatedProposalFromTheForcedToolCall() {
        toolArguments.set("{\"action\":\"revoke-credential\",\"resource\":\"credential:cred-42\",\"purpose\":\"incident-remediation\",\"host\":\"security.example\",\"fields\":[\"incident_id\",\"credential_id\"],\"private_refs\":[]}");

        var result = client().propose("Credential cred-42 leaked in a public paste. Contain it.");

        assertThat(result.proposal().action()).isEqualTo("revoke-credential");
        assertThat(result.proposal().fields()).containsExactly("incident_id", "credential_id");
        JsonNode sent = requests.get(0);
        assertThat(sent.path("tool_choice").path("function").path("name").asText()).isEqualTo("propose_privacy_guard_action");
        assertThat(sent.path("messages").path(0).path("content").asText()).doesNotContain("T3N");
    }

    @Test
    void sensitiveLiteralsNeverReachTheProvider() {
        assertThatThrownBy(() -> client().propose("Notify the owner at someone@example.com about the leak"))
            .isInstanceOf(SensitivePromptRejectedException.class);
        assertThat(requests).isEmpty();
    }

    @Test
    void proposalsThatTryToDecideOrSmuggleValuesAreRejected() {
        for (String arguments : List.of(
            "{\"action\":\"revoke-credential\",\"resource\":\"r\",\"purpose\":\"p\",\"fields\":[],\"decision\":\"ALLOW\"}",
            "{\"action\":\"notify-security\",\"resource\":\"r\",\"purpose\":\"p\",\"fields\":[],\"private_refs\":[\"{{profile.verified_contacts.email.value}}\"]}",
            "{\"action\":\"notify-security\",\"resource\":\"r\",\"purpose\":\"p\",\"fields\":[],\"private_refs\":[\"home_address\"]}",
            "{\"action\":\"\",\"resource\":\"r\",\"purpose\":\"p\",\"fields\":[]}"
        )) {
            toolArguments.set(arguments);
            assertThatThrownBy(() -> client().propose("Contain the incident")).as(arguments).isInstanceOf(InvalidAgentProposalException.class);
        }
    }

    @Test
    void disabledProviderAndUnsafeEndpointsAreRefused() {
        AiAgentClient disabled = new AiAgentClient(new IncidentDataMinimizer(), MAPPER, "disabled", "", "", "", false);
        assertThatThrownBy(() -> disabled.propose("anything")).isInstanceOf(AiProviderUnavailableException.class);

        assertThatThrownBy(() -> AiAgentClient.validateApiUrl("http://models.internal/v1/chat/completions", false)).isInstanceOf(IllegalStateException.class);
        assertThat(AiAgentClient.validateApiUrl("http://models.internal/v1/chat/completions", true).getHost()).isEqualTo("models.internal");
        assertThat(AiAgentClient.validateApiUrl("http://localhost:11434/v1/chat/completions", false).getPort()).isEqualTo(11434);
        assertThatThrownBy(() -> AiAgentClient.validateApiUrl("https://key:secret@api.example/v1", false)).isInstanceOf(IllegalStateException.class);
    }
}
