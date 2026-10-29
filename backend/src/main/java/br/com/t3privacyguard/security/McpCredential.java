package br.com.t3privacyguard.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Bearer token for the MCP endpoint. Without one, /mcp rejects every request. */
@Component
public class McpCredential extends StaticTokenCredential {
    public McpCredential(@Value("${privacy-guard.mcp.token:}") String token) {
        super(token, "MCP_TOKEN");
    }
}
