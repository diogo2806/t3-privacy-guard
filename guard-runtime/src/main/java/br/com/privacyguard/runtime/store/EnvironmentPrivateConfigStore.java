package br.com.privacyguard.runtime.store;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Private configuration from the runtime's own environment, using the variable names the gateway's T3N setup
 * script already read (SECURITY_*, REMEDIATION_AUTH_*). The previous verification key stays valid for the grace
 * period counted from startup, as the setup script counted it from provisioning.
 */
@Component
public class EnvironmentPrivateConfigStore implements PrivateConfigStore {
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._-]{1,32}");
    private static final int MAX_PREVIOUS_KEY_GRACE_SECONDS = 300;
    private static final String PEM_BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static final String PEM_END = "-----END PUBLIC KEY-----";

    private final Map<String, String> entries;

    public EnvironmentPrivateConfigStore(
        @Value("${guard-runtime.remediation.security-api-url:}") String securityApiUrl,
        @Value("${guard-runtime.remediation.security-verification-url:}") String securityVerificationUrl,
        @Value("${guard-runtime.remediation.security-api-key:}") String securityApiKey,
        @Value("${guard-runtime.remediation.authorization.key-id:primary}") String keyId,
        @Value("${guard-runtime.remediation.authorization.public-key-spki:}") String publicKeySpki,
        @Value("${guard-runtime.remediation.authorization.previous-key-id:}") String previousKeyId,
        @Value("${guard-runtime.remediation.authorization.previous-public-key-spki:}") String previousPublicKeySpki,
        @Value("${guard-runtime.remediation.authorization.previous-key-grace-seconds:}") String previousGraceSeconds,
        Clock clock
    ) {
        Map<String, String> values = new HashMap<>();
        putIfPresent(values, "security_api_url", securityApiUrl);
        putIfPresent(values, "security_verification_url", securityVerificationUrl);
        if (present(securityApiKey)) {
            if (securityApiKey.trim().startsWith("replace-with-")) {
                throw new IllegalStateException("SECURITY_API_KEY must be replaced with a runtime-specific value");
            }
            values.put("security_api_key", securityApiKey.trim());
        }

        if (present(publicKeySpki)) {
            String activeKeyId = requireKeyId(keyId, "REMEDIATION_AUTH_KEY_ID");
            values.put("remediation_auth_active_key_id", activeKeyId);
            values.put("remediation_auth_public_key_spki:" + activeKeyId, normalizeEd25519Spki(publicKeySpki, "REMEDIATION_AUTH_PUBLIC_KEY_SPKI"));
        }

        boolean anyPrevious = present(previousKeyId) || present(previousPublicKeySpki) || present(previousGraceSeconds);
        if (anyPrevious) {
            if (!present(previousKeyId) || !present(previousPublicKeySpki) || !present(previousGraceSeconds) || !present(publicKeySpki)) {
                throw new IllegalStateException("REMEDIATION_AUTH_PREVIOUS_KEY_ID, REMEDIATION_AUTH_PREVIOUS_PUBLIC_KEY_SPKI and REMEDIATION_AUTH_PREVIOUS_KEY_GRACE_SECONDS must be configured together with the active key");
            }
            String previousId = requireKeyId(previousKeyId, "REMEDIATION_AUTH_PREVIOUS_KEY_ID");
            if (previousId.equals(values.get("remediation_auth_active_key_id"))) {
                throw new IllegalStateException("REMEDIATION_AUTH_PREVIOUS_KEY_ID must differ from REMEDIATION_AUTH_KEY_ID");
            }
            int grace;
            try {
                grace = Integer.parseInt(previousGraceSeconds.trim());
            } catch (NumberFormatException ex) {
                grace = -1;
            }
            if (grace < 1 || grace > MAX_PREVIOUS_KEY_GRACE_SECONDS) {
                throw new IllegalStateException("REMEDIATION_AUTH_PREVIOUS_KEY_GRACE_SECONDS must be an integer between 1 and " + MAX_PREVIOUS_KEY_GRACE_SECONDS);
            }
            values.put("remediation_auth_public_key_spki:" + previousId, normalizeEd25519Spki(previousPublicKeySpki, "REMEDIATION_AUTH_PREVIOUS_PUBLIC_KEY_SPKI"));
            values.put("remediation_auth_key_valid_until:" + previousId, Long.toString(clock.millis() + grace * 1_000L));
        }
        this.entries = Map.copyOf(values);
    }

    @Override
    public Optional<String> get(String key) {
        return Optional.ofNullable(entries.get(key));
    }

    private static boolean present(String value) {
        return value != null && !value.isBlank();
    }

    private static void putIfPresent(Map<String, String> values, String key, String value) {
        if (present(value)) values.put(key, value.trim());
    }

    private static String requireKeyId(String value, String name) {
        String trimmed = value == null ? "" : value.trim();
        if (!KEY_ID.matcher(trimmed).matches()) throw new IllegalStateException(name + " must match [A-Za-z0-9._-]{1,32}");
        return trimmed;
    }

    /** Same inputs the gateway accepts: DER base64, PEM, or PEM wrapped in base64. Stored as DER base64. */
    static String normalizeEd25519Spki(String value, String name) {
        try {
            String trimmed = value.trim();
            if (!trimmed.startsWith(PEM_BEGIN)) {
                byte[] decoded = Base64.getDecoder().decode(trimmed.replaceAll("\\s+", ""));
                String asText = new String(decoded, StandardCharsets.US_ASCII).trim();
                trimmed = asText.startsWith(PEM_BEGIN) ? asText : Base64.getEncoder().encodeToString(decoded);
            }
            if (trimmed.startsWith(PEM_BEGIN)) {
                int end = trimmed.indexOf(PEM_END);
                if (end < 0 || !trimmed.substring(end + PEM_END.length()).isBlank()) throw new IllegalArgumentException("invalid PEM");
                trimmed = trimmed.substring(PEM_BEGIN.length(), end).replaceAll("\\s+", "");
            }
            byte[] der = Base64.getDecoder().decode(trimmed);
            KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
            return Base64.getEncoder().encodeToString(der);
        } catch (Exception ex) {
            throw new IllegalStateException(name + " must be an Ed25519 SPKI public key encoded as DER base64, PEM, or base64-wrapped PEM");
        }
    }
}
