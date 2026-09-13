package br.com.t3privacyguard.security;

import br.com.t3privacyguard.integration.GatewayRemediationClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("!test")
public class RemediationAuthorizationSigner {
    private static final byte[] ED25519_SPKI_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

    private final ObjectMapper mapper;
    private final PrivateKey privateKey;
    private final String keyId;
    private final Duration ttl;
    private final Supplier<String> executorDidSupplier;

    @Autowired
    public RemediationAuthorizationSigner(
        ObjectMapper mapper,
        GatewayRemediationClient gateway,
        @Value("${privacy-guard.remediation-authorization.private-key}") String privateKeyPkcs8Base64,
        @Value("${privacy-guard.remediation-authorization.public-key}") String publicKeyHex,
        @Value("${privacy-guard.remediation-authorization.key-id}") String keyId,
        @Value("${privacy-guard.remediation-authorization.ttl-seconds:60}") long ttlSeconds
    ) {
        this(mapper, privateKeyPkcs8Base64, publicKeyHex, keyId, ttlSeconds, gateway::requireExecutorDid);
    }

    RemediationAuthorizationSigner(
        ObjectMapper mapper,
        String privateKeyPkcs8Base64,
        String publicKeyHex,
        String keyId,
        long ttlSeconds,
        Supplier<String> executorDidSupplier
    ) {
        if (ttlSeconds < 10 || ttlSeconds > 300) throw new IllegalStateException("REMEDIATION_AUTH_TTL_SECONDS must be between 10 and 300");
        if (keyId == null || !keyId.matches("[A-Za-z0-9._-]{1,32}")) {
            throw new IllegalStateException("REMEDIATION_AUTH_KEY_ID must match [A-Za-z0-9._-]{1,32}");
        }
        this.mapper = mapper;
        this.privateKey = parsePrivateKey(privateKeyPkcs8Base64);
        PublicKey publicKey = parsePublicKey(publicKeyHex);
        validateKeyPair(this.privateKey, publicKey);
        this.keyId = keyId;
        this.ttl = Duration.ofSeconds(ttlSeconds);
        this.executorDidSupplier = executorDidSupplier;
    }

    public String issue(
        String incidentId, String actionId, String requestId, String decisionId, String action,
        String resource, String purpose, String approvedHost, List<String> fields, List<String> privateRefs,
        String policyVersion, String policyHash
    ) {
        if (policyVersion == null || policyVersion.isBlank() || policyHash == null || !policyHash.matches("[a-f0-9]{64}")) {
            throw new IllegalArgumentException("Versioned policy metadata is required for remediation authorization");
        }
        String canonicalApprovedHost = canonicalizeHost(approvedHost);
        String executorDid = executorDidSupplier.get();
        if (executorDid == null || !executorDid.startsWith("did:t3n:")) {
            throw new IllegalStateException("Authenticated protected executor DID is required for remediation authorization");
        }
        Instant now = Instant.now();
        Claims claims = new Claims(
            keyId, incidentId, actionId, requestId, decisionId, action, resource, purpose, canonicalApprovedHost,
            listHash(fields), listHash(privateRefs), policyVersion, policyHash, executorDid,
            now.getEpochSecond(), now.plus(ttl).getEpochSecond(), UUID.randomUUID().toString()
        );
        try {
            byte[] payload = mapper.writeValueAsBytes(claims);
            String encodedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
            String signingInput = "v2." + encodedPayload;
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            String signature = HexFormat.of().formatHex(signer.sign());
            return signingInput + "." + signature;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to issue remediation authorization proof", ex);
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

    private static PrivateKey parsePrivateKey(String value) {
        if (value == null || value.isBlank()) throw new IllegalStateException("REMEDIATION_AUTH_PRIVATE_KEY is required");
        try {
            byte[] encoded = Base64.getDecoder().decode(value.trim());
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
        } catch (Exception ex) {
            throw new IllegalStateException("REMEDIATION_AUTH_PRIVATE_KEY must be a Base64 PKCS#8 Ed25519 private key", ex);
        }
    }

    private static PublicKey parsePublicKey(String value) {
        if (value == null || !value.matches("[a-f0-9]{64}")) {
            throw new IllegalStateException("REMEDIATION_AUTH_PUBLIC_KEY must be a 32-byte lowercase hex Ed25519 public key");
        }
        try {
            byte[] raw = HexFormat.of().parseHex(value);
            byte[] encoded = new byte[ED25519_SPKI_PREFIX.length + raw.length];
            System.arraycopy(ED25519_SPKI_PREFIX, 0, encoded, 0, ED25519_SPKI_PREFIX.length);
            System.arraycopy(raw, 0, encoded, ED25519_SPKI_PREFIX.length, raw.length);
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (Exception ex) {
            throw new IllegalStateException("REMEDIATION_AUTH_PUBLIC_KEY is invalid", ex);
        }
    }

    private static void validateKeyPair(PrivateKey privateKey, PublicKey publicKey) {
        try {
            byte[] challenge = "t3-privacy-guard-remediation-v2".getBytes(StandardCharsets.US_ASCII);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(privateKey);
            signer.update(challenge);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(challenge);
            if (!verifier.verify(signature)) throw new IllegalStateException("Configured remediation authorization keys do not form a pair");
        } catch (IllegalStateException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to validate remediation authorization key pair", ex);
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
        String privateRefsHash,
        String policyVersion,
        String policyHash,
        String executorDid,
        long issuedAt,
        long expiresAt,
        String nonce
    ) {}
}
