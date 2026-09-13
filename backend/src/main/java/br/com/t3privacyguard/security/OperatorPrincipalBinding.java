package br.com.t3privacyguard.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.Normalizer;
import java.util.HexFormat;

public final class OperatorPrincipalBinding {
    public static final int MAX_PRINCIPAL_LENGTH = 120;

    private OperatorPrincipalBinding() {}

    public static String canonicalize(String value) {
        if (value == null) throw new IllegalArgumentException("Authenticated operator principal is required");
        String canonical = Normalizer.normalize(value.strip(), Normalizer.Form.NFKC);
        if (canonical.isBlank() || canonical.length() > MAX_PRINCIPAL_LENGTH || "anonymousUser".equalsIgnoreCase(canonical)) {
            throw new IllegalArgumentException("Authenticated operator principal is invalid");
        }
        if (canonical.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Authenticated operator principal contains control characters");
        }
        return canonical;
    }

    public static String sha256(String principal) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(canonicalize(principal).getBytes(StandardCharsets.UTF_8)));
        } catch (IllegalArgumentException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash authenticated operator principal", ex);
        }
    }
}
