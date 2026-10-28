package br.com.privacyguard.runtime.store;

import java.util.Optional;

/** Replaces the contract's read of the private T3N KV map "privacy-guard-policy" / "current". */
public interface PolicyStore {
    /** Empty when the policy cannot be read at all; the evaluator answers POLICY_UNAVAILABLE. */
    Optional<byte[]> current();
}
