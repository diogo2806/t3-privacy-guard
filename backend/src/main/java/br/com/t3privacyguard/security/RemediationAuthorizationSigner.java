package br.com.t3privacyguard.security;

import br.com.t3privacyguard.integration.GatewayRemediationClient;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class RemediationAuthorizationSigner {
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._-]{1,32}");
    private static final String TOKEN_VERSION = "v2";

    private final ObjectMapper mapper;
    private final PrivateKey privateKey;
    private final String keyId;
    private final Duration ttl;
    private final Supplier<String> executorDidSupplier;

    @Autowired
    public RemediationAuthorizationSigner(
        ObjectMapper mapper,
        GatewayRemediationClient gateway,
        @Value("${privacy-guard.remediation-capability.private-key}") String privateKey,
        @Value("${privacy-guard.remediation-capability.key-id:v1}") String keyId,
        @Value("${privacy-guard.remediation-capability.ttl-seconds:60}") long ttlSeconds
    ) {
        this(mapper, privateKey, keyId, ttlSeconds, gateway::requireExecutorDid);
    }

    RemediationAuthorizationSigner(
        ObjectMapper mapper,
        String encodedPrivateKey,
        String keyId,
        long ttlSeconds,
        Supplier<String> executorDidSupplier
    ) {
        if (keyId == null || !KEY_ID.matcher(keyId).matches()) {
            throw new IllegalStateException("REMEDIATION_AUTH_KEY_ID must match [A-Za-z0-9._-]{1,32}");
        }
        if (ttlSeconds < 10 || ttlSeconds > 300) {
            throw new IllegalStateException("REMEDIATION_CAPABILITY_TTL_SECONDS must be between 10 and 300");
        }
        this.mapper = mapper;
        this.privateKey = decodePrivateKey(encodedPrivateKey);
        this.keyId = keyId;
        this.ttl = Duration.ofSeconds(ttlSeconds);
        this.executorDidSupplier = executorDidSupplier;
    }

    public String issue(
        String incidentId, String actionId, String requestId, String decisionId, String action,
        String resource, String purpose, String approvedHost, List<String> fields, Map<String, String> normalPayload,
        List<String> privateRefs, String policyVersion, String policyHash,
        String remediationAuthorizedBy, Instant remediationAuthorizedAt
    ) {
        if (policyVersion == null || policyVersion.isBlank() || policyHash == null || !policyHash.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Versioned policy metadata is required for remediation authorization");
        }
        String canonicalApprovedHost = canonicalizeHost(approvedHost);
        String executorDid = executorDidSupplier.get();
        if (executorDid == null || !executorDid.startsWith("did:t3n:")) {
            throw new IllegalStateException("Authenticated protected executor DID is required for remediation authorization");
        }
        String operatorPrincipalHash = operatorPrincipalHash(remediationAuthorizedBy);
        if (remediationAuthorizedAt == null) throw new IllegalArgumentException("Persisted human authorization timestamp is required");
        Instant now = Instant.now();
        if (remediationAuthorizedAt.isAfter(now)) throw new IllegalArgumentException("Human authorization timestamp cannot be after capability issuance");
        Claims claims = new Claims(
            keyId, incidentId, actionId, requestId, decisionId, action, resource, purpose, canonicalApprovedHost,
            listHash(fields), NormalPayloadCanonicalizer.sha256(normalPayload), listHash(privateRefs), policyVersion, policyHash, executorDid,
            operatorPrincipalHash, remediationAuthorizedAt.toEpochMilli(), now.toEpochMilli(), now.plus(ttl).toEpochMilli(), UUID.randomUUID().toString()
        );
        try {
            byte[] payload = mapper.writeValueAsBytes(claims);
            String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(encodedPayload.getBytes(StandardCharsets.US_ASCII));
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
            return TOKEN_VERSION + "." + encodedPayload + "." + signature;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to issue remediation authorization proof", ex);
        }
    }

    public static String operatorPrincipalHash(String authenticatedPrincipal) {
        String principal = ActionProposalEntity.canonicalizeAuthenticatedPrincipal(authenticatedPrincipal);
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(principal.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash authenticated operator principal", ex);
        }
    }

    public static String canonicalizeHost(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Approved remediation destination is required");
        String input = value.trim();
        if (input.length() > 253 || input.contains("://") || input.indexOf('/') >= 0 || input.indexOf('@') >= 0
            || input.indexOf(':') >= 0 || input.indexOf('?') >= 0 || input.indexOf('#') >= 0 || input.endsWith(".")) {
            throw new IllegalArgumentException("Approved remediation destination must be a hostname without scheme, port, path or credentials");
        }
        final String ascii;
        try {
            ascii = IDN.toASCII(input, IDN.USE_STD3_ASCII_RULES).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Approved remediation destination is not a valid hostname", ex);
        }
        if (ascii.isBlank() || ascii.length() > 253) throw new IllegalArgumentException("Approved remediation destination is not a valid hostname");
        for (String label : ascii.split("\\.", -1)) {
            if (label.isBlank() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")) {
                throw new IllegalArgumentException("Approved remediation destination is not a valid hostname");
            }
        }
        return ascii;
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

    private static PrivateKey decodePrivateKey(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new IllegalStateException("REMEDIATION_AUTH_PRIVATE_KEY is required as a Base64 PKCS#8 Ed25519 private key");
        }
        try {
            byte[] der;
            try {
                der = Base64.getDecoder().decode(encoded.trim());
            } catch (IllegalArgumentException ignored) {
                der = Base64.getUrlDecoder().decode(encoded.trim());
            }
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception ex) {
            throw new IllegalStateException("REMEDIATION_AUTH_PRIVATE_KEY must be a Base64 PKCS#8 Ed25519 private key", ex);
        }
    }

    public record Claims(
        String keyId,
        String incidentId,
        String actionId,
        String requestId,
        String decisionId,
        String action,
        String resource,
        String purpose,
        String approvedHost,
        String fieldsHash,
        String normalPayloadHash,
        String privateRefsHash,
        String policyVersion,
        String policyHash,
        String executorDid,
        String operatorPrincipalHash,
        long authorizedAt,
        long issuedAt,
        long expiresAt,
        String nonce
    ) {}
}
