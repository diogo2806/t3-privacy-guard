package br.com.t3privacyguard.integration;

/** guard-runtime refused execution before any egress because a newer policy version is active than the approved one. */
public class RemediationPolicyChangedException extends RuntimeException {
    public RemediationPolicyChangedException(String message) { super(message); }
}
