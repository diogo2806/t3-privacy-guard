package br.com.t3privacyguard.observability;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.FilterChain;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class TraceIdFilterTest {
    private final TraceIdFilter filter = new TraceIdFilter();

    @Test
    void preservesSafeTraceAcrossRequestAndResponseThenClearsMdc() throws Exception {
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        String supplied = "trace-safe_1234";
        request.addHeader(TraceContext.HEADER, supplied);
        AtomicReference<String> inside = new AtomicReference<>();
        FilterChain chain = (req, res) -> inside.set(MDC.get(TraceContext.MDC_KEY));

        filter.doFilter(request, response, chain);

        assertThat(inside.get()).isEqualTo(supplied);
        assertThat(response.getHeader(TraceContext.HEADER)).isEqualTo(supplied);
        assertThat(MDC.get(TraceContext.MDC_KEY)).isNull();
    }

    @Test
    void generatesTraceWhenHeaderIsMissing() throws Exception {
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();

        filter.doFilter(request, response, (req, res) -> {});

        assertThat(response.getHeader(TraceContext.HEADER)).matches("[0-9a-f-]{36}");
    }

    @Test
    void replacesMalformedOrOversizedTraceInsteadOfReflectingIt() throws Exception {
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        String malicious = "trace\r\nX-Forged: secret-" + "x".repeat(256);
        request.addHeader(TraceContext.HEADER, malicious);

        filter.doFilter(request, response, (req, res) -> {});

        assertThat(response.getHeader(TraceContext.HEADER)).matches("[0-9a-f-]{36}").isNotEqualTo(malicious);
        assertThat(MDC.get(TraceContext.MDC_KEY)).isNull();
    }
}
