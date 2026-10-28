package br.com.privacyguard.runtime.contract;

/** canonicalize_hostname from authorization.rs and remediation.rs (same rules, caller-specific error text). */
public final class Hostnames {
    private Hostnames() {}

    public static String canonicalize(String value, String errorMessage) {
        String host = ContractText.trim(value);
        if (host.isEmpty() || host.length() > 253 || !ContractText.isAscii(host) || host.endsWith(".")
            || host.contains("://") || host.contains("/") || host.contains("@") || host.contains(":")
            || host.contains("?") || host.contains("#")) {
            throw new ContractRejectedException(errorMessage);
        }
        String canonical = ContractText.asciiLowercase(host);
        for (String label : canonical.split("\\.", -1)) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-") || label.endsWith("-")
                || !label.chars().allMatch(c -> (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) {
                throw new ContractRejectedException(errorMessage);
            }
        }
        return canonical;
    }
}
