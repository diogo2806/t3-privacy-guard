package br.com.privacyguard.runtime.authorization;

import static br.com.privacyguard.runtime.testing.CapabilityTokens.NOW;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.PUBLIC_KEY_SPKI;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.claims;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.revokeRequest;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.sign;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.signedToken;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.withProof;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.remediation.RemediationExecutionRequest;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

/** Port of the tests in authorization.rs, plus cross-runtime hash vectors. */
class CapabilityVerifierTest {
    private static final String EXECUTOR = "agent:executor";

    private static RemediationExecutionRequest request() {
        return revokeRequest(EXECUTOR);
    }

    @Test
    void hashesMatchTheBackendSignerVectors() {
        // Same vector the backend signer uses (and the original TypeScript verifier did).
        assertThat(CapabilityHashes.normalPayloadHash(request().normalPayload()))
            .isEqualTo("39ba6c4944b8e22ae8bb5bb1ebc7d98839593f17d51acd5d5aff31c81ebaa8ae");
        // JSON.stringify([...values].map(trim).sort()) hashed with SHA-256, as the gateway computes it.
        assertThat(CapabilityHashes.listHash(List.of("incident_id", "credential_id", " reason ")))
            .isEqualTo("e921481254ee7c21e4b9e4ba8f5ced564aa784ca10d87936243859c8dfd82625");
        assertThat(CapabilityHashes.listHash(List.of())).isEqualTo("4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945");
        assertThat(CapabilityHashes.listHash(List.of("verified_email"))).isEqualTo("bb3c4afba727c222e26e695a8fa3f654ecbb8dbe7eab3e84a91986765c5f3236");
    }

    @Test
    void validV2ProofIsBoundToKeyExecutionAndHumanProvenance() {
        RemediationExecutionRequest signed = withProof(request(), signedToken(request(), "nonce-00000001"));
        AuthorizationClaims verified = CapabilityVerifier.verify(signed.authorizationProof(), signed, PUBLIC_KEY_SPKI, NOW);
        assertThat(verified.keyId()).isEqualTo("primary");
        assertThat(verified.operatorPrincipalHash()).isEqualTo("b".repeat(64));
        assertThat(verified.authorizedAt()).isLessThanOrEqualTo(verified.issuedAt());
        assertThat(CapabilityVerifier.extractKeyId(signed.authorizationProof())).isEqualTo("primary");
    }

    @Test
    void previousKeyIsAcceptedOnlyInsideExplicitRotationWindow() {
        CapabilityVerifier.validateKeyWindow("primary", "primary", null, NOW);
        CapabilityVerifier.validateKeyWindow("previous", "primary", NOW + 1, NOW);
        assertRejected(() -> CapabilityVerifier.validateKeyWindow("previous", "primary", NOW, NOW), "expired");
        assertRejected(() -> CapabilityVerifier.validateKeyWindow("previous", "primary", null, NOW), "not active");
        assertThatThrownBy(() -> CapabilityVerifier.validateKeyWindow("../bad", "primary", NOW + 1, NOW)).isInstanceOf(ContractRejectedException.class);
    }

    @Test
    void invalidKeyIdDirectExecutionWithoutProofAndLegacyFormatFailClosed() {
        ObjectNode invalid = claims(request(), "nonce-key-0001");
        invalid.put("keyId", "../bad");
        assertRejected(() -> CapabilityVerifier.verify(sign(invalid), request(), PUBLIC_KEY_SPKI, NOW), "key id");
        assertThatThrownBy(() -> CapabilityVerifier.verify("", request(), PUBLIC_KEY_SPKI, NOW)).isInstanceOf(ContractRejectedException.class);
        assertRejected(() -> CapabilityVerifier.verify("legacy.payload", request(), PUBLIC_KEY_SPKI, NOW), "version");
    }

    @Test
    void tamperingBoundPayloadAfterAuthorizationIsRejected() {
        String token = signedToken(request(), "nonce-00000002");
        TreeMap<String, String> tampered = new TreeMap<>(request().normalPayload());
        tampered.put("reason", "tampered");
        RemediationExecutionRequest original = request();
        RemediationExecutionRequest changed = new RemediationExecutionRequest(
            original.incidentId(), original.actionId(), original.decisionId(), original.requestId(), original.agentId(), original.executorId(),
            original.action(), original.resource(), original.purpose(), original.approvedHost(), original.fields(), tampered,
            original.privateRefs(), original.policyVersion(), original.policyHash(), token
        );
        assertRejected(() -> CapabilityVerifier.verify(token, changed, PUBLIC_KEY_SPKI, NOW), "does not match");
    }

    @Test
    void invalidOperatorHashOrAuthorizationTimeIsRejected() {
        ObjectNode invalidHash = claims(request(), "nonce-00000003");
        invalidHash.put("operatorPrincipalHash", "not-a-hash");
        assertThatThrownBy(() -> CapabilityVerifier.verify(sign(invalidHash), request(), PUBLIC_KEY_SPKI, NOW)).isInstanceOf(ContractRejectedException.class);
        ObjectNode futureAuthorization = claims(request(), "nonce-00000004");
        futureAuthorization.put("authorizedAt", NOW + 2_000);
        futureAuthorization.put("issuedAt", NOW + 1_000);
        assertRejected(() -> CapabilityVerifier.verify(sign(futureAuthorization), request(), PUBLIC_KEY_SPKI, NOW), "time bounds");
    }

    @Test
    void alteredSignatureAndExpiredProofAreRejected() {
        String token = signedToken(request(), "nonce-00000005");
        char last = token.charAt(token.length() - 1);
        String altered = token.substring(0, token.length() - 1) + (last == 'A' ? 'B' : 'A');
        assertThatThrownBy(() -> CapabilityVerifier.verify(altered, request(), PUBLIC_KEY_SPKI, NOW)).isInstanceOf(ContractRejectedException.class);
        ObjectNode expired = claims(request(), "nonce-00000006");
        expired.put("issuedAt", NOW - 120_000);
        expired.put("authorizedAt", NOW - 121_000);
        expired.put("expiresAt", NOW - 60_000);
        assertRejected(() -> CapabilityVerifier.verify(sign(expired), request(), PUBLIC_KEY_SPKI, NOW), "expired");
    }

    @Test
    void replayBucketRejectsTheSameNonceTwice() {
        AuthorizationClaims verified = CapabilityVerifier.verify(signedToken(request(), "nonce-00000007"), request(), PUBLIC_KEY_SPKI, NOW);
        ReplayBucket bucket = ReplayBucket.empty().consume(verified, NOW);
        assertRejected(() -> bucket.consume(verified, NOW), "replay");
    }

    // --- Java runtime specifics ---

    @Test
    void executorInTheProofMustBeTheRequestExecutor() {
        String tokenForOtherExecutor = signedToken(revokeRequest("agent:someone-else"), "nonce-00000008");
        assertRejected(() -> CapabilityVerifier.verify(tokenForOtherExecutor, request(), PUBLIC_KEY_SPKI, NOW), "does not match");
    }

    @Test
    void claimsWithFloatTimestampsOrNonCanonicalBase64AreRejected() {
        ObjectNode floatTime = claims(request(), "nonce-00000009");
        floatTime.put("expiresAt", (double) (NOW + 60_000));
        assertRejected(() -> CapabilityVerifier.verify(sign(floatTime), request(), PUBLIC_KEY_SPKI, NOW), "payload is invalid");

        String token = signedToken(request(), "nonce-00000010");
        assertRejected(() -> CapabilityVerifier.verify(token + "=", request(), PUBLIC_KEY_SPKI, NOW), "signature is invalid");
        assertRejected(() -> CapabilityVerifier.verify(token + ".", request(), PUBLIC_KEY_SPKI, NOW), "version");
    }

    @Test
    void expiredBucketEntriesAreDroppedAndCapacityIsBounded() {
        AuthorizationClaims verified = CapabilityVerifier.verify(signedToken(request(), "nonce-00000011"), request(), PUBLIC_KEY_SPKI, NOW);
        ReplayBucket used = ReplayBucket.empty().consume(verified, NOW);
        // After expiry the entry no longer blocks (the capability itself is rejected as expired before this point).
        assertThat(used.consume(verified, NOW + 60_001).entries()).hasSize(1);
    }

    private static void assertRejected(Runnable call, String fragment) {
        assertThatThrownBy(call::run).isInstanceOf(ContractRejectedException.class).hasMessageContaining(fragment);
    }
}
