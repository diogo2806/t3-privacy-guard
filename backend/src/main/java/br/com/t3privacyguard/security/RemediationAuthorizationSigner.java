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
    private static final String TOKEN_VERSION = "v2";
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._-]{1,32}");

    private final ObjectMapper mapper;
    private final PrivateKey privateKey;
    private final String keyId;
    private final Duration ttl;
    private final Supplier<String> executorDidSupplier;

    @Autowired
    public RemediationAuthorizationSigner(
        ObjectMapper mapper,
        GatewayRemediationClient gateway,
        @Value("${privacy-guard.remediation-capability.private-key-pkcs8}") String privateKeyPkcs8,
        @Value("${privacy-guard.remediation-capability.key-id:primary}") String keyId,
        @Value("${privacy-guard.remediation-capability.ttl-seconds:60}") long ttlSeconds
    ) {
        this(mapper, privateKeyPkcs8, keyId, ttlSeconds, gateway::requireExecutorDid);
    }

    RemediationAuthorizationSigner(ObjectMapper mapper, String privateKeyPkcs8, String keyId, long ttlSeconds, Supplier<String> executorDidSupplier) {
        if (ttlSeconds < 10 || ttlSeconds > 300) {
            throw new IllegalStateException("REMEDIATION_CAPABILITY_TTL_SECONDS must be between 10 and 300");
        }
        if (keyId == null || !KEY_ID.matcher(keyId).matches()) {
            throw new IllegalStateException("REMEDIATION_AUTH_KEY_ID must match [A-Za-z0-9._-]{1,32}");
        }
        this.mapper = mapper;
        this.privateKey = parsePrivateKey(privateKeyPkcs8);
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
        requireBoundValue(incidentId, "incidentId");
        requireBoundValue(actionId, "actionId");
        requireBoundValue(requestId, "requestId");
        requireBoundValue(decisionId, "decisionId");
        requireBoundValue(action, "action");
        requireBoundValue(resource, "resource");
        requireBoundValue(purpose, "purpose");
        if (policyVersion == null || policyVersion.isBlank() || policyHash == null || !policyHash.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Versioned policy metadata is required for remediation authorization");
        }
        String canonicalApprovedHost = canonicalizeHost(approvedHost);
        String executorDid = executorDidSupplier.get();
        if (executorDid == null || !executorDid.startsWith("did:t3n:")) {
            throw new IllegalStateException("Authenticated protected executor DID is required for remediation authorization");
        }
        String operatorPrincipalHash = operatorPrincipalHash(remediationAuthorizedBy);
        if (remediationAuthorizedAt == null) {
            throw new IllegalArgumentException("Persisted human authorization timestamp is required");
        }
        Instant now = Instant.now();
        if (remediationAuthorizedAt.isAfter(now)) {
            throw new IllegalArgumentException("Human authorization timestamp cannot be after capability issuance");
        }
        Claims claims = new Claims(
            keyId, incidentId, actionId, requestId, decisionId, action, resource, purpose, canonicalApprovedHost,
            listHash(fields), NormalPayloadCanonicalizer.sha256(normalPayload), listHash(privateRefs), policyVersion, policyHash, executorDid,
            operatorPrincipalHash, remediationAuthorizedAt.toEpochMilli(), now.toEpochMilli(), now.plus(ttl).toEpochMilli(), UUID.randomUUID().toString()
        );
        try {
            byte[] payload = mapper.writeValueAsBytes(claims);
            String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
            String signingInput = TOKEN_VERSION + "." + encodedPayload;
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
            return signingInput + "." + signature;
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

    private static PrivateKey parsePrivateKey(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw new IllegalStateException("REMEDIATION_AUTH_PRIVATE_KEY_PKCS8 is required");
        }
        try {
            byte[] der = Base64.getDecoder().decode(encoded.trim());
            PrivateKey key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
            if (!"EdDSA".equalsIgnoreCase(key.getAlgorithm()) && !"Ed25519".equalsIgnoreCase(key.getAlgorithm())) {
                throw new IllegalStateException("REMEDIATION_AUTH_PRIVATE_KEY_PKCS8 must contain an Ed25519 private key");
            }
            return key;
        } catch (IllegalStateException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("REMEDIATION_AUTH_PRIVATE_KEY_PKCS8 must be a base64 PKCS#8 Ed25519 private key", ex);
        }
    }

    private static void requireBoundValue(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " is required for remediation authorization");
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
