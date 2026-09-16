package br.com.t3privacyguard.security;

import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = "privacy-guard.security-remediation.api-key=0123456789abcdef0123456789abcdef0123456789abcdef")
@AutoConfigureMockMvc
class SecurityRemediationIntegrationTest {
    private static final String API_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef";

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper objectMapper;

    @Test
    void remediationEndpointRejectsAnonymousAndHumanSessionAuthentication() throws Exception {
        mvc.perform(post("/api/security/remediation/execute")
                .contentType(MediaType.APPLICATION_JSON)
                .header("Idempotency-Key", "req-anonymous")
                .content(revokeBody("req-anonymous")))
            .andExpect(status().isUnauthorized());

        mvc.perform(post("/api/security/remediation/execute")
                .with(user("executor-01").roles("EXECUTOR"))
                .contentType(MediaType.APPLICATION_JSON)
                .header("Idempotency-Key", "req-human")
                .content(revokeBody("req-human")))
            .andExpect(status().isForbidden());
    }

    @Test
    void remediationEndpointRejectsInvalidMachineCredential() throws Exception {
        mvc.perform(post("/api/security/remediation/execute")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + "x".repeat(API_KEY.length()))
                .header("Idempotency-Key", "req-invalid")
                .contentType(MediaType.APPLICATION_JSON)
                .content(revokeBody("req-invalid")))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void machineCredentialExecutesAndVerifiesWithoutCsrfOrHumanSession() throws Exception {
        var execution = mvc.perform(post("/api/security/remediation/execute")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + API_KEY)
                .header("Idempotency-Key", "req-live-contract")
                .contentType(MediaType.APPLICATION_JSON)
                .content(revokeBody("req-live-contract")))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.operation_id", matchesPattern("op_[a-f0-9]{32}")))
            .andReturn();

        JsonNode payload = objectMapper.readTree(execution.getResponse().getContentAsByteArray());
        String operationId = payload.get("operation_id").asText();

        mvc.perform(post("/api/security/remediation/verify")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + API_KEY)
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "request_id":"req-live-contract",
                      "operation_id":"%s",
                      "action":"revoke-credential",
                      "expected_state":"REVOKED"
                    }
                    """.formatted(operationId)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.operation_id").value(operationId))
            .andExpect(jsonPath("$.state").value("REVOKED"))
            .andExpect(jsonPath("$.recipient_resolved").doesNotExist())
            .andExpect(jsonPath("$.payload_proof.must_egress_seen").value(false))
            .andExpect(jsonPath("$.payload_proof.must_not_egress_seen").value(false));
    }

    private static String revokeBody(String requestId) {
        return """
            {
              "request_id":"%s",
              "action":"revoke-credential",
              "resource":"credential:cred-1",
              "purpose":"incident-remediation",
              "incident_id":"inc-1",
              "credential_id":"cred-1",
              "reason":"credential exposed"
            }
            """.formatted(requestId);
    }
}
