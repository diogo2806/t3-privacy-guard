package br.com.t3privacyguard.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

public final class NormalPayloadCanonicalizer {
    private static final int MAX_ENTRIES = 16;
    private static final int MAX_KEY_LENGTH = 80;
    private static final int MAX_VALUE_BYTES = 512;
    private static final Pattern KEY_PATTERN = Pattern.compile("[a-z][a-z0-9_]{0,79}");

    private NormalPayloadCanonicalizer() {}

    public static String canonical(Map<String, String> payload) {
        Map<String, String> values = payload == null ? Map.of() : payload;
        if (values.size() > MAX_ENTRIES) throw new IllegalArgumentException("Normal payload exceeds item limit");
        StringBuilder result = new StringBuilder();
        for (var entry : new TreeMap<>(values).entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (key == null || key.length() > MAX_KEY_LENGTH || !KEY_PATTERN.matcher(key).matches()) {
                throw new IllegalArgumentException("Normal payload contains an invalid key");
            }
            if (value == null || value.isBlank() || value.getBytes(StandardCharsets.UTF_8).length > MAX_VALUE_BYTES) {
                throw new IllegalArgumentException("Normal payload contains an invalid value");
            }
            byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
            byte[] valueBytes = value.getBytes(StandardCharsets.UTF_8);
            result.append(keyBytes.length).append(':').append(key)
                .append('=').append(valueBytes.length).append(':').append(value).append('\n');
        }
        return result.toString();
    }

    public static String sha256(Map<String, String> payload) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(canonical(payload).getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash normal remediation payload", ex);
        }
    }
}
