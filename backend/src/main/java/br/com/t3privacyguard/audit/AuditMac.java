package br.com.t3privacyguard.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class AuditMac {
    static final String VERSION = "v1";
    static final String GENESIS = "0".repeat(64);

    private AuditMac() {}

    static String canonicalEvent(
        String keyId,
        String incidentId,
        String eventId,
        long sequence,
        String type,
        Instant createdAt,
        String message,
        Long t3nSequence,
        String t3nHash,
        String t3nFunction,
        String previousMac
    ) {
        return String.join("\n",
            VERSION,
            keyId,
            encoded(incidentId),
            encoded(eventId),
            Long.toString(sequence),
            encoded(type),
            createdAt.toString(),
            encoded(message),
            t3nSequence == null ? "" : Long.toString(t3nSequence),
            encodedNullable(t3nHash),
            encodedNullable(t3nFunction),
            previousMac
        );
    }

    static String canonicalHead(
        String keyId,
        String incidentId,
        long lastSequence,
        String lastEventMac,
        long legacyEventCount,
        Instant updatedAt
    ) {
        return String.join("\n",
            VERSION,
            "HEAD",
            keyId,
            encoded(incidentId),
            Long.toString(lastSequence),
            lastEventMac,
            Long.toString(legacyEventCount),
            updatedAt.toString()
        );
    }

    static String hmacHex(byte[] key, String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to calculate audit integrity MAC", ex);
        }
    }

    static boolean secureHexEquals(String left, String right) {
        if (left == null || right == null || left.length() != 64 || right.length() != 64) return false;
        try {
            return MessageDigest.isEqual(HexFormat.of().parseHex(left), HexFormat.of().parseHex(right));
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static String encoded(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String encodedNullable(String value) {
        return value == null ? "" : encoded(value);
    }
}
