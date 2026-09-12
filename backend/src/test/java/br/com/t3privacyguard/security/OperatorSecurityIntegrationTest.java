package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
            .andExpect(jsonPath("$.authenticated").value(false));
    }

    @Test
    void validLoginCreatesSessionAndAllowsReadOnlyBusinessRequest() throws Exception {
        var result = mvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"test-operator\",\"password\":\"test-password\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.authenticated").value(true))
            .andExpect(jsonPath("$.username").value("test-operator"))
            .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(session).isNotNull();

        mvc.perform(get("/api/incidents").session(session))
            .andExpect(status().isOk());
    }

    @Test
    void invalidCredentialsDoNotRevealWhichFieldWasWrong() throws Exception {
        mvc.perform(post("/api/auth/login")
                .with(csrf())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"test-operator\",\"password\":\"wrong-password\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.detail").value("Invalid operator credentials."));
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
