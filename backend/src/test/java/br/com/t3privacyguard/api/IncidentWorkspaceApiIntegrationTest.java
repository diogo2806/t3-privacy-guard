package br.com.t3privacyguard.api;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class IncidentWorkspaceApiIntegrationTest {
    @Autowired MockMvc mvc;

    @Test
    void anonymousWorkspaceIsBlocked() throws Exception {
        mvc.perform(get("/api/incident-workspace"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void auditorCanReadOperationalQueueWithoutPrivatePayloadFields() throws Exception {
        mvc.perform(get("/api/incident-workspace").with(user("auditor-01").roles("AUDITOR")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.attentionCount").isNumber())
            .andExpect(jsonPath("$.incidents").isArray())
            .andExpect(jsonPath("$.username").doesNotExist())
            .andExpect(jsonPath("$.normalPayload").doesNotExist())
            .andExpect(jsonPath("$.privateRefs").doesNotExist());
    }
}
