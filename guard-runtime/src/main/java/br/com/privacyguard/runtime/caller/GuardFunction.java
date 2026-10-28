package br.com.privacyguard.runtime.caller;

import java.util.Arrays;
import java.util.Optional;

/**
 * Grant vocabulary: the three functions the former contract exported, plus manage-policy for publishing and rolling
 * back policy versions. Each caller gets only what its role needs.
 */
public enum GuardFunction {
    EVALUATE_ACTION("evaluate-action"),
    EXECUTE_REMEDIATION("execute-remediation"),
    VERIFY_REMEDIATION("verify-remediation"),
    MANAGE_POLICY("manage-policy");

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
