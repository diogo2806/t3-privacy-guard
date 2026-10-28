package br.com.privacyguard.runtime.caller;

import java.util.Arrays;
import java.util.Optional;

/**
 * Grant vocabulary: the three functions the former contract exported. Only evaluate-action has an endpoint so far;
 * the other two can already be granted so caller configuration does not change when they are ported.
 */
public enum GuardFunction {
    EVALUATE_ACTION("evaluate-action"),
    EXECUTE_REMEDIATION("execute-remediation"),
    VERIFY_REMEDIATION("verify-remediation");

    private final String wireName;

    GuardFunction(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }

    public static Optional<GuardFunction> fromWireName(String value) {
        return Arrays.stream(values()).filter(function -> function.wireName.equals(value)).findFirst();
    }
}
