package br.com.t3privacyguard.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SecurityRemediationCredential {
    private static final int MIN_TOKEN_LENGTH = 32;
    private static final int MAX_TOKEN_LENGTH = 512;

    private final byte[] tokenBytes;

    public SecurityRemediationCredential(
        @Value("${privacy-guard.security-remediation.api-key:}") String apiKey
    ) {
        String normalized = apiKey == null ? "" : apiKey.trim();
        if (normalized.isEmpty()) {
            this.tokenBytes = null;
            return;
        }
        if (normalized.length() < MIN_TOKEN_LENGTH || normalized.length() > MAX_TOKEN_LENGTH) {
            throw new IllegalStateException("SECURITY_API_KEY must contain between 32 and 512 characters");
        }
        RuntimeSecretPolicy.rejectDocumentationPlaceholder(normalized, "SECURITY_API_KEY");
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
