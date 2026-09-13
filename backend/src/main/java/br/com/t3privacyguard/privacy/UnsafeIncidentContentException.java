package br.com.t3privacyguard.privacy;

public class UnsafeIncidentContentException extends RuntimeException {
    public UnsafeIncidentContentException() {
        super("This content could not be stored safely.");
    }
}
