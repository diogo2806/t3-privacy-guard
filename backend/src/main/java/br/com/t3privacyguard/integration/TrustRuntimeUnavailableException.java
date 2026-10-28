package br.com.t3privacyguard.integration;

public class TrustRuntimeUnavailableException extends RuntimeException {
    public TrustRuntimeUnavailableException(String message) { super(message); }
    public TrustRuntimeUnavailableException(String message, Throwable cause) { super(message, cause); }
}
