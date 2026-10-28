package br.com.privacyguard.runtime.testing;

import br.com.privacyguard.runtime.authorization.CapabilityHashes;
import br.com.privacyguard.runtime.remediation.RemediationExecutionRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Signs v2 capabilities the way the backend does, with the test key pair shared by the Rust and TS tests. */
public final class CapabilityTokens {
    public static final String PRIVATE_KEY_PKCS8 = "MC4CAQAwBQYDK2VwBCIEIAv4OIfbF/R/i9uL6wgRalq2gperSKNx+Ig9BuS9L4qS";
    public static final String PUBLIC_KEY_SPKI = "MCowBQYDK2VwAyEAW3EwSatHmT/ZSgrqu/G3ecXJrTviA5SjAoCwIfwau6A=";
    public static final long NOW = 1_800_000_000_000L;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private CapabilityTokens() {}

    public static RemediationExecutionRequest revokeRequest(String executorId) {
        return new RemediationExecutionRequest(
            "incident-1", "action-1", "decision-1", "request-1", "agent:proposal", executorId,
            "revoke-credential", "credential:test", "incident-remediation", "security-a.example",
            List.of("incident_id", "credential_id", "reason"),
            new TreeMap<>(Map.of("credential_id", "cred-demo-001", "incident_id", "inc-demo-001", "reason", "suspected compromise")),
            List.of(), "2026-09-12.1", "a".repeat(64), "placeholder"
        );
    }

    public static ObjectNode claims(RemediationExecutionRequest request, String nonce) {
        ObjectNode claims = MAPPER.createObjectNode();
        claims.put("keyId", "primary");
        claims.put("incidentId", request.incidentId());
        claims.put("actionId", request.actionId());
        claims.put("requestId", request.requestId());
        claims.put("decisionId", request.decisionId());
        claims.put("action", request.action());
        claims.put("resource", request.resource());
        claims.put("purpose", request.purpose());
        claims.put("approvedHost", request.approvedHost());
        claims.put("fieldsHash", CapabilityHashes.listHash(request.fields()));
        claims.put("normalPayloadHash", CapabilityHashes.normalPayloadHash(request.normalPayload()));
        claims.put("privateRefsHash", CapabilityHashes.listHash(request.privateRefs()));
        claims.put("policyVersion", request.policyVersion());
        claims.put("policyHash", request.policyHash());
        claims.put("executorDid", request.executorId());
        claims.put("operatorPrincipalHash", "b".repeat(64));
        claims.put("authorizedAt", NOW - 2_000);
        claims.put("issuedAt", NOW - 1_000);
        claims.put("expiresAt", NOW + 60_000);
        claims.put("nonce", nonce);
        return claims;
    }

    public static String sign(ObjectNode claims) {
        try {
            String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(MAPPER.writeValueAsBytes(claims));
            String signingInput = "v2." + payload;
            PrivateKey key = KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY_PKCS8)));
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(key);
            signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    public static String signedToken(RemediationExecutionRequest request, String nonce) {
        return sign(claims(request, nonce));
    }

    public static RemediationExecutionRequest withProof(RemediationExecutionRequest request, String proof) {
        return new RemediationExecutionRequest(
            request.incidentId(), request.actionId(), request.decisionId(), request.requestId(), request.agentId(), request.executorId(),
            request.action(), request.resource(), request.purpose(), request.approvedHost(), request.fields(), request.normalPayload(),
            request.privateRefs(), request.policyVersion(), request.policyHash(), proof
        );
    }
}
