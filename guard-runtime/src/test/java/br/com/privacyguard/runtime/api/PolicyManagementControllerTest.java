package br.com.privacyguard.runtime.api;

import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class PolicyManagementControllerTest {
    private static final String PROPOSAL_TOKEN = "test-proposal-agent-token-0123456789abcdef";
    private static final String EXECUTOR_TOKEN = "test-protected-executor-token-0123456789abcdef";
    private static final String ADMIN_TOKEN = "test-policy-admin-token-0123456789abcdef";
    private static final Path WORK = workDirectory();

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    @DynamicPropertySource
    static void runtimeProperties(DynamicPropertyRegistry registry) {
        registry.add("guard-runtime.policy-file", () -> WORK.resolve("seed.json").toString());
        registry.add("guard-runtime.policy-dir", () -> WORK.resolve("policy").toString());
        registry.add("guard-runtime.replay-file", () -> WORK.resolve("replay.json").toString());
        registry.add("guard-runtime.activity-file", () -> WORK.resolve("activity.jsonl").toString());
        registry.add("guard-runtime.callers-json", () -> """
            [{"id":"agent:proposal","token":"%s","functions":["evaluate-action"]},
             {"id":"agent:executor","token":"%s","functions":["execute-remediation","verify-remediation"]},
             {"id":"agent:policy-admin","token":"%s","functions":["manage-policy"]}]"""
            .formatted(PROPOSAL_TOKEN, EXECUTOR_TOKEN, ADMIN_TOKEN));
    }

    @Test
    @Order(1)
    void onlyThePolicyAdminMayReadOrChangePolicy() throws Exception {
        mvc.perform(get("/v1/policy")).andExpect(status().isUnauthorized());
        mvc.perform(get("/v1/policy").header(HttpHeaders.AUTHORIZATION, "Bearer " + PROPOSAL_TOKEN))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.error").value("FUNCTION_NOT_GRANTED"));
        post(EXECUTOR_TOKEN, "/v1/policy/publish", "{}")
            .andExpect(status().isForbidden())
            .andExpect(header().exists(ContractFunctionController.ACTIVITY_SEQUENCE_HEADER));
    }

    @Test
    @Order(2)
    void returnsTheSeededPolicyAsTheCurrentVersion() throws Exception {
        mvc.perform(get("/v1/policy").header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.managed").value(true))
            .andExpect(jsonPath("$.state").value("AVAILABLE"))
            .andExpect(jsonPath("$.version").value("2026-09-16.1"))
            .andExpect(jsonPath("$.hash").value(matchesPattern("[a-f0-9]{64}")))
            .andExpect(jsonPath("$.document.actions['revoke-credential'].allowed_fields.length()").value(3));
        mvc.perform(get("/v1/policy/history").header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.total").value(1))
            .andExpect(jsonPath("$.entries[0].operation").value("seed"));
    }

    @Test
    @Order(3)
    void validateReportsTheContractReasonWithoutSaving() throws Exception {
        String candidate = documentWithVersion("v-invalid").replace("\"credential_id\"", "\"api_key\"");
        post(ADMIN_TOKEN, "/v1/policy/validate", "{\"document\":" + candidate + "}")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(false))
            .andExpect(jsonPath("$.reason").value("policy attempts to allow a contract-forbidden secret field"));
        post(ADMIN_TOKEN, "/v1/policy/validate", "{\"document\":" + documentWithVersion("v-ok") + "}")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.valid").value(true))
            .andExpect(jsonPath("$.version").value("v-ok"));
        mvc.perform(get("/v1/policy/history").header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN))
            .andExpect(jsonPath("$.total").value(1));
    }

    @Test
    @Order(4)
    void publishThenEvaluationUsesTheNewVersionAndRollbackRestoresTheOldOne() throws Exception {
        String seedHash = currentHash();
        String body = "{\"document\":" + documentWithVersion("2026-10-28.2") + ",\"expected_current_hash\":\"" + seedHash
            + "\",\"requested_by\":\"alice\"}";

        post(ADMIN_TOKEN, "/v1/policy/publish", body)
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.changed").value(true))
            .andExpect(jsonPath("$.version").value("2026-10-28.2"))
            .andExpect(jsonPath("$.previous_version").value("2026-09-16.1"))
            .andExpect(header().exists(ContractFunctionController.ACTIVITY_SEQUENCE_HEADER));
        post(PROPOSAL_TOKEN, "/v1/functions/evaluate-action", revoke())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.policy_version").value("2026-10-28.2"));

        post(ADMIN_TOKEN, "/v1/policy/publish", body)
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.error").value("POLICY_CHANGED"));

        post(ADMIN_TOKEN, "/v1/policy/rollback", "{\"version\":\"2026-09-16.1\",\"expected_current_hash\":\"" + currentHash()
            + "\",\"requested_by\":\"bob\"}")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.hash").value(seedHash));
        mvc.perform(get("/v1/policy/history").header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN))
            .andExpect(jsonPath("$.entries[0].operation").value("rollback"))
            .andExpect(jsonPath("$.entries[0].requested_by").value("bob"))
            .andExpect(jsonPath("$.entries[1].requested_by").value("alice"))
            .andExpect(jsonPath("$.entries[1].caller").value("agent:policy-admin"));
        mvc.perform(get("/v1/policy/versions/2026-10-28.2").header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.version").value("2026-10-28.2"));
        mvc.perform(get("/v1/policy/versions/never").header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN))
            .andExpect(status().isNotFound());
    }

    @Test
    @Order(5)
    void rejectsMalformedRequests() throws Exception {
        post(ADMIN_TOKEN, "/v1/policy/publish", "{\"document\":{},\"unexpected\":true}").andExpect(status().isBadRequest());
        post(ADMIN_TOKEN, "/v1/policy/publish", "{\"document\":" + documentWithVersion("v9") + ",\"expected_current_hash\":\"" + currentHash()
            + "\",\"requested_by\":\"has space\"}").andExpect(status().isBadRequest());
        post(ADMIN_TOKEN, "/v1/policy/publish", "{\"document\":" + documentWithVersion("2026-10-28.2").replace("incident-remediation", "other")
            + ",\"expected_current_hash\":\"" + currentHash() + "\"}")
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.error").value("VERSION_EXISTS"));
    }

    private String currentHash() throws Exception {
        String json = mvc.perform(get("/v1/policy").header(HttpHeaders.AUTHORIZATION, "Bearer " + ADMIN_TOKEN))
            .andReturn().getResponse().getContentAsString();
        return mapper.readTree(json).path("hash").asText();
    }

    private String documentWithVersion(String version) throws IOException {
        JsonNode document = mapper.readTree(Files.readString(Path.of("policy/privacy-guard-policy.json")));
        ((com.fasterxml.jackson.databind.node.ObjectNode) document).put("version", version);
        return mapper.writeValueAsString(document);
    }

    private ResultActions post(String token, String path, String body) throws Exception {
        return mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(path)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .content(body));
    }

    private static String revoke() {
        return """
            {"request_id":"req-policy-1","agent_did":"agent:proposal","action":"revoke-credential","resource":"credential:demo",
            "purpose":"incident-remediation","host":"security-api.internal","fields":["incident_id"],"private_refs":[]}""";
    }

    private static Path workDirectory() {
        try {
            Path directory = Files.createTempDirectory("guard-runtime-policy-admin");
            directory.toFile().deleteOnExit();
            Files.copy(Path.of("policy/privacy-guard-policy.json"), directory.resolve("seed.json"));
            return directory;
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
