package br.com.t3privacyguard.integration;

public class GatewayUnavailableException extends RuntimeException {
    public GatewayUnavailableException(String message) { super(message); }
    public GatewayUnavailableException(String message, Throwable cause) { super(message, cause); }
}
