package br.com.t3privacyguard.security;

import java.security.Principal;

public record IncidentIntakePrincipal(String integrationId, String displayName) implements Principal {
    @Override
    public String getName() {
        return integrationId;
    }
}
