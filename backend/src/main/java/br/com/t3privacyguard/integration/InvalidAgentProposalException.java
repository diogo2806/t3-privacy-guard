package br.com.t3privacyguard.integration;

/** The model answered, but not with exactly one well-formed, policy-safe proposal. Nothing is persisted. */
public class InvalidAgentProposalException extends RuntimeException {
    public InvalidAgentProposalException(String code) { super(code); }
}
