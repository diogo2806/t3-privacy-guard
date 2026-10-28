package br.com.t3privacyguard.security;

import java.util.regex.Pattern;

/**
 * Identity of the Protected Executor as the trust runtime reports it: a did:t3n: DID on Terminal 3 or a caller id
 * such as agent:executor on the self-hosted guard-runtime. The capability binds to whatever the gateway reports;
 * this only rejects values that are missing or not a safe opaque identifier.
 */
public final class ProtectedExecutorIdentity {
    private static final Pattern IDENTITY = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");

    private ProtectedExecutorIdentity() {}

    public static boolean isValid(String value) {
        return value != null && IDENTITY.matcher(value).matches();
    }
}
