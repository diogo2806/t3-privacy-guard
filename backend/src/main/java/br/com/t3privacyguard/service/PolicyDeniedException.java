package br.com.t3privacyguard.service;

public class PolicyDeniedException extends RuntimeException {
    public PolicyDeniedException(String message) { super(message); }
}
