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
class BusinessImpactApiIntegrationTest {
    @Autowired
    MockMvc mvc;

    @Test
    void anonymousImpactReadIsBlocked() throws Exception {
        mvc.perform(get("/api/business-impact"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void auditorCanReadAggregateWithoutPrivateOperationalValues() throws Exception {
        mvc.perform(get("/api/business-impact")
                .param("window", "retained")
                .with(user("auditor-01").roles("AUDITOR")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.window").value("RETAINED"))
            .andExpect(jsonPath("$.evaluatedActions").isNumber())
            .andExpect(jsonPath("$.deniedBeforeEgress").isNumber())
            .andExpect(jsonPath("$.humanAuthorizedRemediations").isNumber())
            .andExpect(jsonPath("$.finalizedExecutions").isNumber())
            .andExpect(jsonPath("$.from").exists())
            .andExpect(jsonPath("$.to").exists())
            .andExpect(jsonPath("$.username").doesNotExist())
            .andExpect(jsonPath("$.normalPayload").doesNotExist())
            .andExpect(jsonPath("$.privateRefs").doesNotExist());
    }

    @Test
    void unsupportedWindowReturnsBadRequest() throws Exception {
        mvc.perform(get("/api/business-impact")
                .param("window", "30d")
                .with(user("auditor-01").roles("AUDITOR")))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.title").value("Invalid business impact window"));
    }
}
