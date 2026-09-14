package br.com.t3privacyguard.service;

public class ExternalIncidentExpiredException extends RuntimeException {
    public ExternalIncidentExpiredException() {
        super("The retained idempotency record for this external event has expired. Use a new externalEventId after the incident retention window.");
    }
}
