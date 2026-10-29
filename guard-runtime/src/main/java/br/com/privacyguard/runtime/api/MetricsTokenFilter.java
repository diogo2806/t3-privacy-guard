package br.com.privacyguard.runtime.api;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** /actuator/prometheus only for the scraper holding the metrics token; without a token configured, for nobody. */
@Component
public class MetricsTokenFilter extends OncePerRequestFilter {
    private final byte[] token;

    public MetricsTokenFilter(@Value("${guard-runtime.metrics-token:}") String token) {
        String normalized = token == null ? "" : token.trim();
        if (!normalized.isEmpty() && (normalized.length() < 32 || normalized.length() > 512)) {
            throw new IllegalStateException("GUARD_RUNTIME_METRICS_TOKEN must contain between 32 and 512 characters");
        }
        this.token = normalized.isEmpty() ? null : normalized.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/actuator/prometheus");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String presented = ContractFunctionController.bearerToken(request.getHeader(HttpHeaders.AUTHORIZATION));
        if (token == null || presented == null || !MessageDigest.isEqual(presented.getBytes(StandardCharsets.UTF_8), token)) {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"guard-runtime-metrics\"");
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        chain.doFilter(request, response);
    }
}
