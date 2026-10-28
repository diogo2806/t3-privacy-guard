package br.com.privacyguard.runtime.store;

import br.com.privacyguard.runtime.policy.AppliedPolicy;
import java.util.List;
import java.util.Optional;

/**
 * A policy store with immutable versions and a hash-chained history, so an administrator can publish a new version or
 * roll back to an earlier one while the runtime is running. Every change names the caller that made it and, when the
 * app supplies it, the human who requested it.
 */
public interface ManagedPolicyStore extends PolicyStore {
    Optional<AppliedPolicy> currentPolicy();

    Optional<AppliedPolicy> version(String version);

    /** Oldest first. */
    List<HistoryEntry> history();

    /**
     * Makes the document the current policy. {@code expectedCurrentHash} must be the hash of the current policy (null
     * when there is none), so two administrators cannot overwrite each other's change unknowingly.
     */
    Change publish(byte[] document, String expectedCurrentHash, String callerId, String requestedBy);

    /** Makes an already published version current again. */
    Change rollback(String version, String expectedCurrentHash, String callerId, String requestedBy);

    record Change(boolean changed, String version, String hash, String previousVersion, String previousHash) {}

    record HistoryEntry(
        long sequence,
        String entryHash,
        long timestampMs,
        String operation,
        String version,
        String policyHash,
        String previousVersion,
        String previousPolicyHash,
        String caller,
        String requestedBy
    ) {}

    /** A refused change; {@code code} is the API error code. */
    final class PolicyChangeException extends RuntimeException {
        public static final String POLICY_INVALID = "POLICY_INVALID";
        public static final String POLICY_CHANGED = "POLICY_CHANGED";
        public static final String VERSION_EXISTS = "VERSION_EXISTS";
        public static final String VERSION_NOT_FOUND = "VERSION_NOT_FOUND";

        private final String code;

        public PolicyChangeException(String code, String message) {
            super(message);
            this.code = code;
        }

        public String code() {
            return code;
        }
    }
}
