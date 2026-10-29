package br.com.t3privacyguard.security;

public class McpAuthenticationFilter extends StaticTokenAuthenticationFilter {
    public static final String MCP_AUTHORITY = "SCOPE_mcp:tools";

    public McpAuthenticationFilter(McpCredential credential) {
        super(credential, "mcp-client", MCP_AUTHORITY);
    }
}
