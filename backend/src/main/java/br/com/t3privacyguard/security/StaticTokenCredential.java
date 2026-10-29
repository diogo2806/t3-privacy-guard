package br.com.t3privacyguard.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** A machine-to-machine bearer token from configuration. Empty means the endpoint it guards rejects every request. */
public abstract class StaticTokenCredential {
    private static final int MIN_TOKEN_LENGTH = 32;
    private static final int MAX_TOKEN_LENGTH = 512;

    private final byte[] tokenBytes;

    protected StaticTokenCredential(String token, String name) {
        String normalized = token == null ? "" : token.trim();
        if (normalized.isEmpty()) {
            this.tokenBytes = null;
            return;
        }
        if (normalized.length() < MIN_TOKEN_LENGTH || normalized.length() > MAX_TOKEN_LENGTH) {
            throw new IllegalStateException(name + " must contain between 32 and 512 characters");
        }
        RuntimeSecretPolicy.rejectDocumentationPlaceholder(normalized, name);
        this.tokenBytes = normalized.getBytes(StandardCharsets.UTF_8);
    }

    public boolean isConfigured() {
        return tokenBytes != null;
    }

    public boolean matches(String candidate) {
        if (tokenBytes == null || candidate == null || candidate.length() < MIN_TOKEN_LENGTH || candidate.length() > MAX_TOKEN_LENGTH) {
            return false;
        }
        return MessageDigest.isEqual(candidate.getBytes(StandardCharsets.UTF_8), tokenBytes);
    }
}
