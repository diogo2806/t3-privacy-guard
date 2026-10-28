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

public class McpAuthenticationFilter extends OncePerRequestFilter {
    public static final String MCP_AUTHORITY = "SCOPE_mcp:tools";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String PRINCIPAL = "mcp-client";

    private final McpCredential credential;

    public McpAuthenticationFilter(McpCredential credential) {
        this.credential = credential;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            String token = header.substring(BEARER_PREFIX.length()).trim();
            if (credential.matches(token)) {
                SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(PRINCIPAL, null, List.of(new SimpleGrantedAuthority(MCP_AUTHORITY)))
                );
            }
        }
        filterChain.doFilter(request, response);
    }
}
