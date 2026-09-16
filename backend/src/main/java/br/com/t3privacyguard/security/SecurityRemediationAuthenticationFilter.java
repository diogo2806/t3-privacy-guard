package br.com.t3privacyguard.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

public class SecurityRemediationAuthenticationFilter extends OncePerRequestFilter {
    public static final String REMEDIATION_AUTHORITY = "SCOPE_security:remediation";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String PRINCIPAL = "t3n-protected-remediation";

    private final SecurityRemediationCredential credential;

    public SecurityRemediationAuthenticationFilter(SecurityRemediationCredential credential) {
        this.credential = credential;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            if (credential.matches(token)) {
                var authentication = new UsernamePasswordAuthenticationToken(
                    PRINCIPAL,
                    null,
                    List.of(new SimpleGrantedAuthority(REMEDIATION_AUTHORITY))
                );
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }
        filterChain.doFilter(request, response);
    }
}
