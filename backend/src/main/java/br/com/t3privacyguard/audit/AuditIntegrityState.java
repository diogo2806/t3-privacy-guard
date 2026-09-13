package br.com.t3privacyguard.audit;

public enum AuditIntegrityState {
    VERIFIED,
    BROKEN,
    KEY_MISMATCH,
    LEGACY_UNVERIFIED,
    PURGED,
    NOT_AVAILABLE
}
