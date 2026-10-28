package br.com.privacyguard.runtime.api;

import static org.hamcrest.Matchers.nullValue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import org.junit.jupiter.api.Test;
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
class ContractFunctionControllerTest {
    private static final String PROPOSAL_TOKEN = "test-proposal-agent-token-0123456789abcdef";
    private static final String EXECUTOR_TOKEN = "test-protected-executor-token-0123456789abcdef";
    private static final String REPOSITORY_POLICY_HASH = "b0bbf68eb05dcb056076b3957ab512f31729cc0869a9d5162deaf11f034c42da";
    private static final Path POLICY_FILE = copyRepositoryPolicy();

    @Autowired
    private MockMvc mvc;

    @DynamicPropertySource
    static void runtimeProperties(DynamicPropertyRegistry registry) {
        registry.add("guard-runtime.policy-file", POLICY_FILE::toString);
        registry.add("guard-runtime.replay-file", () -> POLICY_FILE.resolveSibling("replay.json").toString());
        registry.add("guard-runtime.callers-json", () -> """
            [{"id":"agent:proposal","token":"%s","functions":["evaluate-action"]},
             {"id":"agent:executor","token":"%s","functions":["execute-remediation","verify-remediation"]}]"""
            .formatted(PROPOSAL_TOKEN, EXECUTOR_TOKEN));
    }

    @Test
    void rejectsMissingOrUnknownCredentials() throws Exception {
        mvc.perform(post("/v1/functions/evaluate-action").contentType(MediaType.APPLICATION_JSON).content(revoke("incident_id")))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").value("UNAUTHENTICATED"));
        call("unknown-token-0123456789abcdef-0123456789", revoke("incident_id")).andExpect(status().isUnauthorized());
    }

    @Test
    void rejectsCallerWithoutTheFunctionGrant() throws Exception {
        call(EXECUTOR_TOKEN, revoke("incident_id"))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.error").value("FUNCTION_NOT_GRANTED"));
    }

    @Test
    void allowsMinimalRequestWithTheSamePolicyHashAsTheContract() throws Exception {
        call(PROPOSAL_TOKEN, revoke("incident_id\",\"credential_id\",\"reason"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.decision").value("ALLOW"))
            .andExpect(jsonPath("$.reason_code").value("POLICY_ALLOW"))
            .andExpect(jsonPath("$.allowed_fields.length()").value(3))
            .andExpect(jsonPath("$.policy_version").value("2026-09-16.1"))
            .andExpect(jsonPath("$.policy_hash").value(REPOSITORY_POLICY_HASH))
            .andExpect(jsonPath("$.requires_human_authorization").value(true));
    }

    @Test
    void redactsFieldsTheActionDoesNotNeed() throws Exception {
        call(PROPOSAL_TOKEN, revoke("incident_id\",\"credential_id\",\"reason\",\"employee_department"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.decision").value("REDACT"))
            .andExpect(jsonPath("$.redacted_fields[0]").value("employee_department"));
    }

    @Test
    void deniesSecretDisclosure() throws Exception {
        call(PROPOSAL_TOKEN, revoke("incident_id\",\"api_key"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.decision").value("DENY"))
            .andExpect(jsonPath("$.reason_code").value("SECRET_DISCLOSURE_FORBIDDEN"));
    }

    @Test
    void deniesAgentIdentityThatIsNotTheAuthenticatedCaller() throws Exception {
        call(PROPOSAL_TOKEN, revoke("incident_id").replace("agent:proposal", "agent:executor"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.decision").value("DENY"))
            .andExpect(jsonPath("$.reason_code").value("INVALID_AGENT_DID"));
    }

    @Test
    void rejectsMalformedAndOversizedInput() throws Exception {
        call(PROPOSAL_TOKEN, "{\"request_id\": 42}").andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").value("INVALID_INPUT"));
        call(PROPOSAL_TOKEN, "{\"pad\":\"" + "x".repeat(ContractFunctionController.MAX_INPUT_BYTES) + "\"}")
            .andExpect(status().isPayloadTooLarge());
    }

    @Test
    void failsClosedWhenThePolicyCannotBeRead() throws Exception {
        Path parked = POLICY_FILE.resolveSibling("parked.json");
        Files.move(POLICY_FILE, parked, StandardCopyOption.REPLACE_EXISTING);
        try {
            call(PROPOSAL_TOKEN, revoke("incident_id"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.decision").value("DENY"))
                .andExpect(jsonPath("$.reason_code").value("POLICY_UNAVAILABLE"))
                .andExpect(jsonPath("$.policy_hash").value(nullValue()));
        } finally {
            Files.move(parked, POLICY_FILE, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @Test
    void remediationFunctionsAreGrantedOnlyToTheExecutor() throws Exception {
        call(PROPOSAL_TOKEN, "/v1/functions/execute-remediation", execution("v2.a.b")).andExpect(status().isForbidden());
        call(PROPOSAL_TOKEN, "/v1/functions/verify-remediation", verification()).andExpect(status().isForbidden());
    }

    @Test
    void remediationRejectionsCarryTheContractReason() throws Exception {
        call(EXECUTOR_TOKEN, "/v1/functions/execute-remediation", "{\"request_id\":1}")
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.error").value("INVALID_INPUT"));
        call(EXECUTOR_TOKEN, "/v1/functions/execute-remediation", execution("v1.legacy.proof"))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.error").value("CONTRACT_REJECTED"))
            .andExpect(jsonPath("$.reason").value("authorization proof version is unsupported"));
        call(EXECUTOR_TOKEN, "/v1/functions/verify-remediation", verification())
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.reason").value("required private configuration security_verification_url is missing"));
    }

    private static String execution(String proof) {
        return """
            {"incident_id":"inc-1","action_id":"act-1","decision_id":"dec-1","request_id":"req-1","agent_did":"agent:proposal",
             "executor_did":"agent:executor","action":"revoke-credential","resource":"credential:cred-42","purpose":"incident-remediation",
             "approved_host":"security-api.internal","fields":["incident_id","credential_id","reason"],
             "normal_payload":{"incident_id":"inc-1","credential_id":"cred-42","reason":"leak"},"private_refs":[],
             "policy_version":"2026-09-16.1","policy_hash":"%s","authorization_proof":"%s"}""".formatted(REPOSITORY_POLICY_HASH, proof);
    }

    private static String verification() {
        return "{\"request_id\":\"req-1\",\"operation_id\":\"op-1\",\"action\":\"revoke-credential\",\"expected_state\":\"REVOKED\"}";
    }

    private ResultActions call(String token, String path, String body) throws Exception {
        return mvc.perform(post(path)
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .content(body));
    }

    private ResultActions call(String token, String body) throws Exception {
        return mvc.perform(post("/v1/functions/evaluate-action")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .content(body));
    }

    private static String revoke(String fields) {
        return """
            {"request_id":"req-001","agent_did":"agent:proposal","action":"revoke-credential","resource":"credential:cred-42",
             "purpose":"incident-remediation","host":"postman-echo.com","fields":["%s"],"private_refs":[]}""".formatted(fields);
    }

    private static Path copyRepositoryPolicy() {
        try {
            Path directory = Files.createTempDirectory("guard-runtime-policy");
            directory.toFile().deleteOnExit();
            Path target = directory.resolve("current.json");
            Files.copy(Path.of("../t3n-gateway/policy/privacy-guard-policy.json"), target);
            target.toFile().deleteOnExit();
            return target;
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }
}
