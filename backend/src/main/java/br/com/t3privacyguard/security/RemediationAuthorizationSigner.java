package br.com.t3privacyguard.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class RemediationAuthorizationSigner {
    private final ObjectMapper mapper;
    private final byte[] key;
    private final Duration ttl;

    public RemediationAuthorizationSigner(
        ObjectMapper mapper,
        @Value("${privacy-guard.remediation-capability.key}") String key,
        @Value("${privacy-guard.remediation-capability.ttl-seconds:60}") long ttlSeconds
    ) {
        if (key == null || key.length() < 32) throw new IllegalStateException("REMEDIATION_CAPABILITY_KEY must contain at least 32 characters");
        if (ttlSeconds < 10 || ttlSeconds > 300) throw new IllegalStateException("REMEDIATION_CAPABILITY_TTL_SECONDS must be between 10 and 300");
        this.mapper = mapper;
        this.key = key.getBytes(StandardCharsets.UTF_8);
        this.ttl = Duration.ofSeconds(ttlSeconds);
    }

    public String issue(
        String incidentId, String actionId, String requestId, String decisionId, String action,
        String resource, String purpose, List<String> fields, List<String> privateRefs,
        String policyVersion, String policyHash
    ) {
        if (policyVersion == null || policyVersion.isBlank() || policyHash == null || !policyHash.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Versioned policy metadata is required for remediation authorization");
        }
        Instant now = Instant.now();
        Claims claims = new Claims(
            incidentId, actionId, requestId, decisionId, action, resource, purpose,
            listHash(fields), listHash(privateRefs), policyVersion, policyHash,
            now.toEpochMilli(), now.plus(ttl).toEpochMilli(), UUID.randomUUID().toString()
        );
        try {
            byte[] payload = mapper.writeValueAsBytes(claims);
            String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(encodedPayload.getBytes(StandardCharsets.US_ASCII)));
            return encodedPayload + "." + signature;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to issue remediation authorization proof", ex);
        }
    }

    private String listHash(List<String> values) {
        try {
            List<String> canonical = values == null ? List.of() : values.stream().map(String::trim).sorted().toList();
            byte[] json = mapper.writeValueAsBytes(canonical);
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(json));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash remediation metadata", ex);
        }
    }

    public record Claims(
        String incidentId,
        String actionId,
        String requestId,
        String decisionId,
        String action,
        String resource,
        String purpose,
        String fieldsHash,
        String privateRefsHash,
        String policyVersion,
        String policyHash,
        long authorizedAt,
        long expiresAt,
        String nonce
    ) {}
}
