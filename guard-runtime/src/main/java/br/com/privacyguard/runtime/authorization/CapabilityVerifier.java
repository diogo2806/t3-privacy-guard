package br.com.privacyguard.runtime.authorization;

import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.contract.ContractText;
import br.com.privacyguard.runtime.contract.Hostnames;
import br.com.privacyguard.runtime.remediation.RemediationExecutionRequest;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

/** Port of the pure part of authorization.rs: token format, Ed25519 signature, time bounds and request bindings. */
public final class CapabilityVerifier {
    static final String TOKEN_VERSION = "v2";
    private static final int MAX_TOKEN_BYTES = 8_192;
    private static final long MAX_CAPABILITY_LIFETIME_MS = 300_000;
    private static final long CLOCK_SKEW_MS = 5_000;
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._-]{1,32}");
    private static final Pattern NONCE = Pattern.compile("[A-Za-z0-9._:-]{8,128}");
    private static final Pattern BASE64_URL_PART = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern EXECUTOR_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final Pattern SHA256_HEX = Pattern.compile("[0-9a-f]{64}");
    private static final String HOST_ERROR = "authorization proof contains an invalid approved host";

    private CapabilityVerifier() {}

    static boolean validKeyId(String value) {
        return KEY_ID.matcher(value).matches();
    }

    static void validateKeyWindow(String claimedKeyId, String activeKeyId, Long previousValidUntilMs, long nowMs) {
        if (!validKeyId(claimedKeyId) || !validKeyId(activeKeyId)) {
            throw new ContractRejectedException("authorization verification key id is invalid");
        }
        if (claimedKeyId.equals(activeKeyId)) return;
        if (previousValidUntilMs == null) throw new ContractRejectedException("authorization verification key version is not active");
        if (previousValidUntilMs <= nowMs) throw new ContractRejectedException("authorization verification key rotation window expired");
    }

    public static String extractKeyId(String token) {
        return decodeClaims(tokenParts(token)[1]).keyId();
    }

    public static AuthorizationClaims verify(String token, RemediationExecutionRequest request, String publicKeySpki, long nowMs) {
        String[] parts = tokenParts(token);
        AuthorizationClaims claims = decodeClaims(parts[1]);
        byte[] signature = decodeUrlBase64(parts[2], "authorization proof signature is invalid");
        PublicKey publicKey = publicKey(publicKeySpki);
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.UTF_8);
        if (!signatureMatches(publicKey, signingInput, signature)) {
            throw new ContractRejectedException("authorization proof signature is invalid");
        }
        validateTime(claims, nowMs);
        validateBindings(claims, request);
        return claims;
    }

    private static String[] tokenParts(String token) {
        if (token.isEmpty() || ContractText.utf8Length(token) > MAX_TOKEN_BYTES) {
            throw new ContractRejectedException("authorization proof is missing or exceeds the size limit");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || !parts[0].equals(TOKEN_VERSION)) {
            throw new ContractRejectedException("authorization proof version is unsupported");
        }
        return parts;
    }

    private static AuthorizationClaims decodeClaims(String payloadPart) {
        if (!BASE64_URL_PART.matcher(payloadPart).matches()) throw new ContractRejectedException("authorization proof payload is invalid");
        byte[] payload = decodeUrlBase64(payloadPart, "authorization proof payload is invalid");
        AuthorizationClaims claims = AuthorizationClaims.parseOrNull(payload);
        if (claims == null) throw new ContractRejectedException("authorization proof payload is invalid");
        if (!validKeyId(claims.keyId())) throw new ContractRejectedException("authorization proof key id is invalid");
        return claims;
    }

    /** URL_SAFE_NO_PAD with the base64 crate's strictness: no padding and no non-zero trailing bits. */
    private static byte[] decodeUrlBase64(String value, String error) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value);
            if (!Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)) throw new ContractRejectedException(error);
            return decoded;
        } catch (IllegalArgumentException ex) {
            throw new ContractRejectedException(error);
        }
    }

    private static PublicKey publicKey(String spki) {
        try {
            byte[] der = Base64.getDecoder().decode(ContractText.trim(spki));
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (IllegalArgumentException | GeneralSecurityException ex) {
            throw new ContractRejectedException("authorization verification key is invalid");
        }
    }

    private static boolean signatureMatches(PublicKey publicKey, byte[] signingInput, byte[] signature) {
        if (signature.length != 64) return false;
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(publicKey);
            verifier.update(signingInput);
            return verifier.verify(signature);
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

    private static void validateTime(AuthorizationClaims claims, long nowMs) {
        if (claims.authorizedAt() == 0 || claims.issuedAt() == 0
            || claims.authorizedAt() > claims.issuedAt()
            || claims.expiresAt() <= claims.issuedAt()
            || claims.expiresAt() - claims.issuedAt() > MAX_CAPABILITY_LIFETIME_MS) {
            throw new ContractRejectedException("authorization proof time bounds are invalid");
        }
        if (claims.expiresAt() <= nowMs) throw new ContractRejectedException("authorization proof expired");
        if (claims.issuedAt() > nowMs + CLOCK_SKEW_MS) throw new ContractRejectedException("authorization proof was issued in the future");
    }

    /** The contract required a did:t3n: executor; here any caller id, which must then equal the request's executor. */
    private static void validateBindings(AuthorizationClaims claims, RemediationExecutionRequest request) {
        if (!EXECUTOR_ID.matcher(claims.executorId()).matches() || !NONCE.matcher(claims.nonce()).matches()) {
            throw new ContractRejectedException("authorization proof contains invalid provenance metadata");
        }
        if (!SHA256_HEX.matcher(claims.fieldsHash()).matches() || !SHA256_HEX.matcher(claims.normalPayloadHash()).matches()
            || !SHA256_HEX.matcher(claims.privateRefsHash()).matches() || !SHA256_HEX.matcher(claims.policyHash()).matches()
            || !SHA256_HEX.matcher(claims.operatorPrincipalHash()).matches() || ContractText.trim(claims.policyVersion()).isEmpty()) {
            throw new ContractRejectedException("authorization proof contains invalid binding metadata");
        }
        String requestHost = Hostnames.canonicalize(request.approvedHost(), HOST_ERROR);
        String claimsHost = Hostnames.canonicalize(claims.approvedHost(), HOST_ERROR);
        boolean mismatched = !claims.incidentId().equals(request.incidentId())
            || !claims.actionId().equals(request.actionId())
            || !claims.requestId().equals(request.requestId())
            || !claims.decisionId().equals(request.decisionId())
            || !claims.action().equals(request.action())
            || !claims.resource().equals(request.resource())
            || !claims.purpose().equals(request.purpose())
            || !claimsHost.equals(requestHost)
            || !claims.fieldsHash().equals(CapabilityHashes.listHash(request.fields()))
            || !claims.normalPayloadHash().equals(CapabilityHashes.normalPayloadHash(request.normalPayload()))
            || !claims.privateRefsHash().equals(CapabilityHashes.listHash(request.privateRefs()))
            || !claims.policyVersion().equals(request.policyVersion())
            || !claims.policyHash().equals(request.policyHash())
            || !claims.executorId().equals(request.executorId());
        if (mismatched) throw new ContractRejectedException("authorization proof does not match the remediation request");
    }
}
