package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class OperatorSecurityIntegrationTest {
    @Autowired
    MockMvc mvc;

    @Test
    void anonymousBusinessApiIsBlocked() throws Exception {
        mvc.perform(get("/api/incidents"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.detail").value("Your operator session has expired. Sign in again to continue."));
    }

    @Test
    void sessionEndpointDoesNotPretendAnonymousUserIsAuthenticated() throws Exception {
        mvc.perform(get("/api/auth/session"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.authenticated").value(false))
            .andExpect(jsonPath("$.authorities").isArray())
            .andExpect(jsonPath("$.enterpriseSeparationOfDuties").value(false));
    }

    @Test
    void validLocalLoginExposesSemanticAuthoritiesWithoutClaimingEnterpriseSod() throws Exception {
        var result = mvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"test-operator\",\"password\":\"test-password\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.authenticated").value(true))
            .andExpect(jsonPath("$.username").value("test-operator"))
            .andExpect(jsonPath("$.authorities", containsInAnyOrder("ANALYST", "APPROVER", "EXECUTOR", "AUDITOR")))
            .andExpect(jsonPath("$.enterpriseSeparationOfDuties").value(false))
            .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session).isNotNull();

        mvc.perform(get("/api/incidents").session(session))
            .andExpect(status().isOk());
    }

    @Test
    void analystCannotAuthorizeRemediation() throws Exception {
        mvc.perform(post("/api/incidents/i/actions/a/authorize-remediation")
                .with(user("analyst-01").roles("ANALYST"))
                .with(csrf()))
            .andExpect(status().isForbidden())
            .andExpect(jsonPath("$.detail").value("Your session role is not allowed to perform this action."));
    }

    @Test
    void approverCannotExecuteRemediation() throws Exception {
        mvc.perform(post("/api/incidents/i/actions/a/execute-remediation")
                .with(user("approver-01").roles("APPROVER"))
                .with(csrf()))
            .andExpect(status().isForbidden());
    }

    @Test
    void executorCannotAuthorizeRemediation() throws Exception {
        mvc.perform(post("/api/incidents/i/actions/a/authorize-remediation")
                .with(user("executor-01").roles("EXECUTOR"))
                .with(csrf()))
            .andExpect(status().isForbidden());
    }

    @Test
    void auditorIsReadOnlyForBusinessMutations() throws Exception {
        mvc.perform(post("/api/incidents")
                .with(user("auditor-01").roles("AUDITOR"))
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"title\":\"Test\",\"severity\":\"HIGH\",\"summary\":\"Test\",\"source\":\"security-test\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void auditorCanReachReadOnlyAuditEndpoint() throws Exception {
        mvc.perform(get("/api/incidents/missing/history")
                .with(user("auditor-01").roles("AUDITOR")))
            .andExpect(status().isNotFound());
    }

    @Test
    void invalidCredentialsDoNotRevealWhichFieldWasWrong() throws Exception {
        mvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"single-failure-user\",\"password\":\"wrong-password\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.detail").value("Invalid operator credentials."));
    }

    @Test
    void repeatedFailuresReturn429WithRetryAfterWithoutUserEnumeration() throws Exception {
        String body = "{\"username\":\"rate-limit-target\",\"password\":\"wrong-password\"}";
        for (int attempt = 1; attempt < OperatorLoginAttemptGuard.FAILURE_THRESHOLD; attempt++) {
            mvc.perform(post("/api/auth/login")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid operator credentials."));
        }

        mvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isTooManyRequests())
            .andExpect(header().string("Retry-After", matchesPattern("[1-9][0-9]*")))
            .andExpect(jsonPath("$.detail").value("Too many failed attempts. Try again after the cooldown."));

        mvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
            .andExpect(status().isTooManyRequests())
            .andExpect(jsonPath("$.detail").value("Too many failed attempts. Try again after the cooldown."));
    }

    @Test
    void authenticatedMutationWithoutCsrfIsBlocked() throws Exception {
        var login = mvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"test-operator\",\"password\":\"test-password\"}"))
            .andExpect(status().isOk())
            .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

        mvc.perform(post("/api/incidents")
                .session(session)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"title\":\"Test\",\"severity\":\"HIGH\",\"summary\":\"Test\",\"source\":\"security-test\"}"))
            .andExpect(status().isForbidden());
    }

    @Test
    void logoutInvalidatesTheOperatorSession() throws Exception {
        var login = mvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"test-operator\",\"password\":\"test-password\"}"))
            .andExpect(status().isOk())
            .andReturn();
        MockHttpSession session = (MockHttpSession) login.getRequest().getSession(false);

        mvc.perform(post("/api/auth/logout").session(session).with(csrf()))
            .andExpect(status().isNoContent());

        assertThat(session.isInvalid()).isTrue();
    }
}
