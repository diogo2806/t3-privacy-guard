package br.com.privacyguard.runtime.egress;

/** The http-with-placeholders error variants of the T3N host interface. */
public class EgressException extends RuntimeException {
    public enum Kind { EGRESS_DENIED, PLACEHOLDER_DENIED, PLACEHOLDER_UNKNOWN, PLACEHOLDER_NO_USER_CONTEXT, UPSTREAM_ERROR }

    private final Kind kind;

    public EgressException(Kind kind, String detail) {
        super(detail);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
