package br.com.t3privacyguard.integration;

/** guard-runtime refused or cannot perform a policy administration request. The message is safe to show. */
public class PolicyAdministrationException extends RuntimeException {
    public enum Kind {
        /** No admin token, the token lacks manage-policy, or guard-runtime keeps policy as a read-only file. */
        UNAVAILABLE,
        /** The current policy changed since it was read, or the version was already published. */
        CONFLICT,
        NOT_FOUND,
        /** The document breaks a policy rule; the message is guard-runtime's reason. */
        INVALID
    }

    private final Kind kind;
    private final String code;

    public PolicyAdministrationException(Kind kind, String code, String message) {
        super(message);
        this.kind = kind;
        this.code = code;
    }

    public Kind kind() {
        return kind;
    }

    public String code() {
        return code;
    }
}
