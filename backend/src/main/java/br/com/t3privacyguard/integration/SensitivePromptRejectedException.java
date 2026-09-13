package br.com.t3privacyguard.integration;

public class SensitivePromptRejectedException extends RuntimeException {
    public SensitivePromptRejectedException() {
        super("Remove literal private values and use an approved logical reference instead.");
    }
}
