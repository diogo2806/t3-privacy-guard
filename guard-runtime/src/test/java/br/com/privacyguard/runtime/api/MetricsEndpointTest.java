package br.com.privacyguard.runtime.api;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** Function calls are counted by function and outcome, and the metrics endpoint needs the metrics token. */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureObservability
class MetricsEndpointTest {
    private static final String PROPOSAL_TOKEN = "test-proposal-agent-token-0123456789abcdef";
    private static final String METRICS_TOKEN = "test-metrics-token-0123456789abcdef0123";
    private static final Path WORK = workDirectory();

    @Autowired
    private MockMvc mvc;

    @DynamicPropertySource
    static void runtimeProperties(DynamicPropertyRegistry registry) {
        registry.add("guard-runtime.policy-file", () -> WORK.resolve("current.json").toString());
        registry.add("guard-runtime.replay-file", () -> WORK.resolve("replay.json").toString());
        registry.add("guard-runtime.activity-file", () -> WORK.resolve("activity.jsonl").toString());
        registry.add("guard-runtime.metrics-token", () -> METRICS_TOKEN);
        registry.add("guard-runtime.callers-json", () ->
            "[{\"id\":\"agent:proposal\",\"token\":\"" + PROPOSAL_TOKEN + "\",\"functions\":[\"evaluate-action\"]}]");
    }

    @Test
    void countsCallsAndProtectsTheEndpoint() throws Exception {
        mvc.perform(post("/v1/functions/evaluate-action").header(HttpHeaders.AUTHORIZATION, "Bearer " + PROPOSAL_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {"request_id":"req-metrics","agent_did":"agent:proposal","action":"revoke-credential","resource":"credential:x",
                     "purpose":"incident-remediation","host":"postman-echo.com","fields":["incident_id","api_key"],"private_refs":[]}"""))
            .andExpect(status().isOk());

        mvc.perform(get("/actuator/prometheus")).andExpect(status().isUnauthorized());
        mvc.perform(get("/actuator/prometheus").header(HttpHeaders.AUTHORIZATION, "Bearer " + METRICS_TOKEN))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("guard_runtime_calls_total{function=\"evaluate-action\",outcome=\"success\"")));
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }

    private static Path workDirectory() {
        try {
            Path directory = Files.createTempDirectory("guard-runtime-metrics");
            directory.toFile().deleteOnExit();
            Files.copy(Path.of("policy/privacy-guard-policy.json"), directory.resolve("current.json"));
            return directory;
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
