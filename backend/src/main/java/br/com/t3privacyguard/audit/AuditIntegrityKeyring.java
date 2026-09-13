package br.com.t3privacyguard.audit;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public final class AuditIntegrityKeyring {
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._-]{1,32}");

    private final String currentKeyId;
    private final Map<String, byte[]> keys;

    public AuditIntegrityKeyring(
        @Value("${privacy-guard.audit-integrity.key}") String currentKey,
        @Value("${privacy-guard.audit-integrity.key-id:primary}") String currentKeyId,
        @Value("${privacy-guard.audit-integrity.previous-keys:}") String previousKeys,
        @Value("${privacy-guard.gateway.service-token:}") String gatewayServiceToken,
        @Value("${privacy-guard.remediation-capability.key:}") String remediationCapabilityKey,
        @Value("${privacy-guard.operator.password:}") String operatorPassword
    ) {
        validateKeyId(currentKeyId, "AUDIT_INTEGRITY_KEY_ID");
        validateSecret(currentKey, "AUDIT_INTEGRITY_KEY");
        rejectReuse(currentKey, gatewayServiceToken, "GATEWAY_SERVICE_TOKEN");
        rejectReuse(currentKey, remediationCapabilityKey, "REMEDIATION_CAPABILITY_KEY");
        rejectReuse(currentKey, operatorPassword, "OPERATOR_PASSWORD");

        Map<String, byte[]> configured = new LinkedHashMap<>();
        configured.put(currentKeyId, currentKey.getBytes(StandardCharsets.UTF_8));
        parsePrevious(previousKeys, configured, currentKeyId, currentKey);
        this.currentKeyId = currentKeyId;
        this.keys = Map.copyOf(configured);
    }

    public String currentKeyId() {
        return currentKeyId;
    }

    public byte[] currentKey() {
        return keys.get(currentKeyId).clone();
    }

    public Optional<byte[]> resolve(String keyId) {
        byte[] key = keys.get(keyId);
        return key == null ? Optional.empty() : Optional.of(key.clone());
    }

    private static void parsePrevious(String raw, Map<String, byte[]> configured, String currentKeyId, String currentKey) {
        if (raw == null || raw.isBlank()) return;
        for (String entry : raw.split(",")) {
            String candidate = entry.trim();
            if (candidate.isEmpty()) continue;
            int separator = candidate.indexOf('=');
            if (separator <= 0 || separator == candidate.length() - 1) {
                throw new IllegalStateException("AUDIT_INTEGRITY_PREVIOUS_KEYS must use keyId=secret entries separated by commas");
            }
            String keyId = candidate.substring(0, separator).trim();
            String secret = candidate.substring(separator + 1).trim();
            validateKeyId(keyId, "AUDIT_INTEGRITY_PREVIOUS_KEYS key id");
            validateSecret(secret, "AUDIT_INTEGRITY_PREVIOUS_KEYS secret");
            if (keyId.equals(currentKeyId)) throw new IllegalStateException("Previous audit key id must differ from AUDIT_INTEGRITY_KEY_ID");
            if (secret.equals(currentKey)) throw new IllegalStateException("Previous audit integrity keys must not reuse the current key material");
            if (configured.putIfAbsent(keyId, secret.getBytes(StandardCharsets.UTF_8)) != null) {
                throw new IllegalStateException("Duplicate audit integrity key id: " + keyId);
            }
        }
    }

    private static void validateKeyId(String value, String name) {
        if (value == null || !KEY_ID.matcher(value).matches()) {
            throw new IllegalStateException(name + " must match [A-Za-z0-9._-]{1,32}");
        }
    }

    private static void validateSecret(String value, String name) {
        if (value == null || value.length() < 32) throw new IllegalStateException(name + " must contain at least 32 characters");
        if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0 || value.indexOf(',') >= 0) {
            throw new IllegalStateException(name + " must not contain line breaks or commas");
        }
    }

    private static void rejectReuse(String auditKey, String otherSecret, String otherName) {
        if (otherSecret != null && !otherSecret.isBlank() && auditKey.equals(otherSecret)) {
            throw new IllegalStateException("AUDIT_INTEGRITY_KEY must be different from " + otherName);
        }
    }
}
