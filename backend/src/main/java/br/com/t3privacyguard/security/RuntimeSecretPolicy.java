package br.com.t3privacyguard.security;

public final class RuntimeSecretPolicy {
    private static final String DOCUMENTATION_PLACEHOLDER_PREFIX = "replace-with-";

    private RuntimeSecretPolicy() {}

    public static void rejectDocumentationPlaceholder(String value, String name) {
        if (value != null && value.trim().startsWith(DOCUMENTATION_PLACEHOLDER_PREFIX)) {
            throw new IllegalStateException(name + " must be replaced with a runtime-specific value");
        }
    }
}
