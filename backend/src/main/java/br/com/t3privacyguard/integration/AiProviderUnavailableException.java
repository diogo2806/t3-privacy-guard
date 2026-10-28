package br.com.t3privacyguard.integration;

public class AiProviderUnavailableException extends RuntimeException {
    public AiProviderUnavailableException(String message) { super(message); }
    public AiProviderUnavailableException(String message, Throwable cause) { super(message, cause); }
}
