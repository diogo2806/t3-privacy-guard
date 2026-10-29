package br.com.t3privacyguard.api;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.micrometer.core.instrument.Metrics;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

/** Prometheus metrics are served only to the scraper holding METRICS_TOKEN, never to a browser session. */
@SpringBootTest
@AutoConfigureMockMvc
@AutoConfigureObservability
class MetricsEndpointTest {
    @Autowired MockMvc mvc;

    @Test
    void requiresTheMetricsToken() throws Exception {
        mvc.perform(get("/actuator/prometheus")).andExpect(status().isUnauthorized());
        mvc.perform(get("/actuator/prometheus").header(HttpHeaders.AUTHORIZATION, "Bearer wrong-token-0000000000000000000000000"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void exposesRuntimeAndProductMetrics() throws Exception {
        Metrics.counter("privacy_guard.decisions", "decision", "DENY").increment();
        mvc.perform(get("/actuator/prometheus").header(HttpHeaders.AUTHORIZATION, "Bearer test-metrics-token-1234567890123456789012"))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("jvm_memory_used_bytes")))
            .andExpect(content().string(containsString("privacy_guard_decisions_total{decision=\"DENY\"")));
    }
}
