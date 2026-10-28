package br.com.t3privacyguard.api;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import br.com.t3privacyguard.integration.PolicyAdministrationException;
import br.com.t3privacyguard.integration.PolicyAdministrationException.Kind;
import br.com.t3privacyguard.integration.RuntimePolicyAdminClient;
import br.com.t3privacyguard.integration.RuntimePolicyAdminClient.PolicyChange;
import br.com.t3privacyguard.integration.RuntimePolicyAdminClient.PolicyView;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class PolicyControllerTest {
    private static final String HASH = "a".repeat(64);
    private static final String PUBLISH = "{\"document\":{\"version\":\"v2\",\"actions\":{}},\"expectedCurrentHash\":\"" + HASH + "\"}";

    @Autowired MockMvc mvc;
    @MockitoBean RuntimePolicyAdminClient policies;

    @Test
    void auditorsCanReadButNotChangePolicy() throws Exception {
        when(policies.current()).thenReturn(new PolicyView(true, true, "AVAILABLE", "v1", HASH, null, null));

        mvc.perform(get("/api/policy").with(user("audit").roles("AUDITOR")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.version").value("v1"))
            .andExpect(jsonPath("$.managed").value(true));
        mvc.perform(post("/api/policy/publish").with(user("audit").roles("AUDITOR")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(PUBLISH))
            .andExpect(status().isForbidden());
        verify(policies, never()).publish(any(), any(), any());
    }

    @Test
    void operationalRolesCannotSeeThePolicyEditor() throws Exception {
        mvc.perform(get("/api/policy").with(user("analyst").roles("ANALYST"))).andExpect(status().isForbidden());
        mvc.perform(get("/api/policy/history").with(user("approver").roles("APPROVER"))).andExpect(status().isForbidden());
    }

    @Test
    void policyAdminPublishesAsTheAuthenticatedPrincipal() throws Exception {
        when(policies.publish(any(), eq(HASH), eq("policy-admin")))
            .thenReturn(new PolicyChange(true, "v2", "b".repeat(64), "v1", HASH));

        mvc.perform(post("/api/policy/publish").with(user("policy-admin").roles("POLICY_ADMIN")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(PUBLISH))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.changed").value(true))
            .andExpect(jsonPath("$.previousVersion").value("v1"));
    }

    @Test
    void publishingWithoutCsrfIsRejected() throws Exception {
        mvc.perform(post("/api/policy/publish").with(user("policy-admin").roles("POLICY_ADMIN"))
                .contentType(MediaType.APPLICATION_JSON).content(PUBLISH))
            .andExpect(status().isForbidden());
    }

    @Test
    void runtimeRefusalsBecomeProblemResponses() throws Exception {
        when(policies.publish(any(), any(), any()))
            .thenThrow(new PolicyAdministrationException(Kind.INVALID, "POLICY_INVALID", "policy attempts to allow a contract-forbidden secret field"));
        mvc.perform(post("/api/policy/publish").with(user("policy-admin").roles("POLICY_ADMIN")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(PUBLISH))
            .andExpect(status().isUnprocessableEntity())
            .andExpect(jsonPath("$.code").value("POLICY_INVALID"))
            .andExpect(jsonPath("$.detail").value("policy attempts to allow a contract-forbidden secret field"));

        when(policies.rollback(any(), any(), any()))
            .thenThrow(new PolicyAdministrationException(Kind.CONFLICT, "POLICY_CHANGED", "The policy changed since you opened it."));
        mvc.perform(post("/api/policy/rollback").with(user("policy-admin").roles("POLICY_ADMIN")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content("{\"version\":\"v1\",\"expectedCurrentHash\":\"" + HASH + "\"}"))
            .andExpect(status().isConflict())
            .andExpect(jsonPath("$.code").value("POLICY_CHANGED"));
    }

    @Test
    void aDocumentThatIsNotAnObjectIsRejectedBeforeReachingTheRuntime() throws Exception {
        mvc.perform(post("/api/policy/validate").with(user("policy-admin").roles("POLICY_ADMIN")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content("{\"document\":[1,2]}"))
            .andExpect(status().isUnprocessableEntity());
        verify(policies, never()).validate(any());
    }

    @Test
    void thePolicyAdminCanStillUseTheRestOfTheDashboardReadOnly() throws Exception {
        mvc.perform(get("/api/auth/session").with(user("policy-admin").roles("POLICY_ADMIN")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.authorities[0]").value("POLICY_ADMIN"));
        mvc.perform(post("/api/incidents").with(user("policy-admin").roles("POLICY_ADMIN")).with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isForbidden());
    }
}
