package br.com.privacyguard.runtime.authorization;

import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.contract.ContractText;
import br.com.privacyguard.runtime.remediation.RemediationExecutionRequest;
import br.com.privacyguard.runtime.store.PrivateConfigStore;
import java.util.Optional;
import org.springframework.stereotype.Component;

/** verify_and_consume from authorization.rs: resolve the key version, verify the capability, burn its nonce. */
@Component
public class RemediationAuthorizer {
    private final PrivateConfigStore secrets;
    private final ReplayStore replays;

    public RemediationAuthorizer(PrivateConfigStore secrets, ReplayStore replays) {
        this.secrets = secrets;
        this.replays = replays;
    }

    public void verifyAndConsume(RemediationExecutionRequest request, long nowMs) {
        String keyId = CapabilityVerifier.extractKeyId(request.authorizationProof());
        String publicKey = readVerificationKey(keyId, nowMs);
        AuthorizationClaims claims = CapabilityVerifier.verify(request.authorizationProof(), request, publicKey, nowMs);
        replays.consume(claims, nowMs);
    }

    private String readVerificationKey(String keyId, long nowMs) {
        if (!CapabilityVerifier.validKeyId(keyId)) throw new ContractRejectedException("authorization proof key id is invalid");
        String activeKeyId = ContractText.trim(secrets.get("remediation_auth_active_key_id")
            .orElseThrow(() -> new ContractRejectedException("authorization active verification key id is not provisioned")));
        Long previousValidUntilMs = null;
        if (!keyId.equals(activeKeyId)) {
            Optional<String> raw = secrets.get("remediation_auth_key_valid_until:" + keyId);
            if (raw.isPresent()) previousValidUntilMs = parseValidUntil(raw.get());
        }
        CapabilityVerifier.validateKeyWindow(keyId, activeKeyId, previousValidUntilMs, nowMs);
        return secrets.get("remediation_auth_public_key_spki:" + keyId)
            .orElseThrow(() -> new ContractRejectedException("authorization verification key version is not provisioned"));
    }

    private static long parseValidUntil(String raw) {
        try {
            long value = Long.parseLong(ContractText.trim(raw));
            if (value < 0) throw new NumberFormatException();
            return value;
        } catch (NumberFormatException ex) {
            throw new ContractRejectedException("authorization verification key rotation window is invalid");
        }
    }
}
