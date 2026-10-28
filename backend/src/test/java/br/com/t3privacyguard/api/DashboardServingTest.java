package br.com.t3privacyguard.api;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

/** The backend serves the dashboard build itself; only the static files are public. */
@SpringBootTest
@AutoConfigureMockMvc
class DashboardServingTest {
    @Autowired MockMvc mvc;

    @Test
    void dashboardIsPublicAndCarriesTheSecurityHeaders() throws Exception {
        mvc.perform(get("/index.html"))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("<div id=\"root\">")))
            .andExpect(header().string("Content-Security-Policy", containsString("default-src 'self'")))
            .andExpect(header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
            .andExpect(header().string("Referrer-Policy", "no-referrer"))
            .andExpect(header().string("X-Frame-Options", "DENY"))
            .andExpect(header().string("Permissions-Policy", containsString("camera=()")));
        mvc.perform(get("/")).andExpect(status().isOk());
    }

    @Test
    void apiStillRequiresAnOperatorSession() throws Exception {
        mvc.perform(get("/api/system/status")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/incidents")).andExpect(status().isUnauthorized());
    }
}
