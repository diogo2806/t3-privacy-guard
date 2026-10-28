package br.com.privacyguard.runtime.authorization;

/** Replaces the private T3N KV map "privacy-guard-execution-nonces". */
public interface ReplayStore {
    /** Records the capability nonce or throws ContractRejectedException if it was already used. */
    void consume(AuthorizationClaims claims, long nowMs);
}
