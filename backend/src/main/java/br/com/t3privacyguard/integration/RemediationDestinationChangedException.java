package br.com.t3privacyguard.integration;

public class RemediationDestinationChangedException extends RuntimeException {
    public RemediationDestinationChangedException(String message) { super(message); }
    public RemediationDestinationChangedException(String message, Throwable cause) { super(message, cause); }
}
