package br.com.t3privacyguard.audit;

public class AuditIntegrityException extends RuntimeException {
    public AuditIntegrityException(String message) {
        super(message);
    }
}
