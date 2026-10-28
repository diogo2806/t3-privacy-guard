package br.com.t3privacyguard.api;

import br.com.t3privacyguard.audit.AuditIntegrityException;
import br.com.t3privacyguard.integration.AiProviderUnavailableException;
import br.com.t3privacyguard.integration.InvalidAgentProposalException;
import br.com.t3privacyguard.integration.PolicyAdministrationException;
import br.com.t3privacyguard.integration.SensitivePromptRejectedException;
import br.com.t3privacyguard.integration.TrustRuntimeUnavailableException;
import br.com.t3privacyguard.privacy.UnsafeIncidentContentException;
import br.com.t3privacyguard.security.TooManyLoginAttemptsException;
import br.com.t3privacyguard.service.*;
import java.net.URI;
import org.springframework.http.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(IncidentNotFoundException.class)
    ResponseEntity<ProblemDetail> notFound(IncidentNotFoundException ex) { return problem(HttpStatus.NOT_FOUND, "Resource not found", ex.getMessage()); }

    @ExceptionHandler(ConflictException.class)
    ResponseEntity<ProblemDetail> conflict(ConflictException ex) { return problem(HttpStatus.CONFLICT, "Request conflict", ex.getMessage()); }

    @ExceptionHandler(ExternalIncidentExpiredException.class)
    ResponseEntity<ProblemDetail> expiredExternalIncident(ExternalIncidentExpiredException ex) {
        return problem(HttpStatus.GONE, "External event id expired", ex.getMessage());
    }

    @ExceptionHandler(AuditIntegrityException.class)
    ResponseEntity<ProblemDetail> auditIntegrity(AuditIntegrityException ex) {
        return problem(HttpStatus.CONFLICT, "Audit integrity check failed", "Local audit history is not verifiable. Protected changes are blocked until the integrity failure is investigated.");
    }

    @ExceptionHandler(PolicyDeniedException.class)
    ResponseEntity<ProblemDetail> denied(PolicyDeniedException ex) { return problem(HttpStatus.FORBIDDEN, "Policy denied remediation", ex.getMessage()); }

    @ExceptionHandler(AuthenticationException.class)
    ResponseEntity<ProblemDetail> authentication(AuthenticationException ex) { return problem(HttpStatus.UNAUTHORIZED, "Authentication failed", "Invalid operator credentials."); }

    @ExceptionHandler(TooManyLoginAttemptsException.class)
    ResponseEntity<ProblemDetail> loginRateLimited(TooManyLoginAttemptsException ex) {
        ProblemDetail body = problemBody(HttpStatus.TOO_MANY_REQUESTS, "Sign-in temporarily limited", "Too many failed attempts. Try again after the cooldown.");
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .header(HttpHeaders.RETRY_AFTER, Long.toString(ex.retryAfterSeconds()))
            .body(body);
    }

    @ExceptionHandler(SensitivePromptRejectedException.class)
    ResponseEntity<ProblemDetail> sensitivePrompt(SensitivePromptRejectedException ex) {
        return problem(HttpStatus.UNPROCESSABLE_ENTITY, "Sensitive prompt rejected", "Remove literal private values and use an approved logical reference such as verified email instead.");
    }

    @ExceptionHandler(UnsafeIncidentContentException.class)
    ResponseEntity<ProblemDetail> unsafeIncident(UnsafeIncidentContentException ex) {
        return problem(HttpStatus.UNPROCESSABLE_ENTITY, "Incident content rejected", "This content could not be stored safely. Remove literal personal data, credentials, tokens or secrets and retry with operational metadata only.");
    }

    @ExceptionHandler(TrustRuntimeUnavailableException.class)
    ResponseEntity<ProblemDetail> trustRuntime(TrustRuntimeUnavailableException ex) { return problem(HttpStatus.SERVICE_UNAVAILABLE, "Trust runtime unavailable", "The action was not authorized because guard-runtime could not complete the check."); }

    @ExceptionHandler(AiProviderUnavailableException.class)
    ResponseEntity<ProblemDetail> aiProvider(AiProviderUnavailableException ex) { return problem(HttpStatus.SERVICE_UNAVAILABLE, "AI agent unavailable", "The AI agent provider is not configured or did not answer. No action was proposed."); }

    @ExceptionHandler(InvalidAgentProposalException.class)
    ResponseEntity<ProblemDetail> invalidProposal(InvalidAgentProposalException ex) { return problem(HttpStatus.UNPROCESSABLE_ENTITY, "Invalid agent proposal", "The AI agent returned an invalid or unsafe structured proposal. Nothing was stored or evaluated."); }

    @ExceptionHandler(PolicyAdministrationException.class)
    ResponseEntity<ProblemDetail> policyAdministration(PolicyAdministrationException ex) {
        HttpStatus status = switch (ex.kind()) {
            case UNAVAILABLE, CONFLICT -> HttpStatus.CONFLICT;
            case NOT_FOUND -> HttpStatus.NOT_FOUND;
            case INVALID -> HttpStatus.UNPROCESSABLE_ENTITY;
        };
        ProblemDetail body = problemBody(status, "Policy change refused", ex.getMessage());
        body.setProperty("code", ex.code());
        return ResponseEntity.status(status).body(body);
    }

    @ExceptionHandler(InvalidBusinessImpactWindowException.class)
    ResponseEntity<ProblemDetail> invalidBusinessImpactWindow(InvalidBusinessImpactWindowException ex) {
        return problem(HttpStatus.BAD_REQUEST, "Invalid business impact window", ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ProblemDetail> validation(MethodArgumentNotValidException ex) { return problem(HttpStatus.BAD_REQUEST, "Invalid request", "One or more request fields are invalid."); }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ProblemDetail> unexpected(Exception ex) {
        // Spring MVC's own errors (missing static file, wrong method or media type) keep their 4xx status.
        if (ex instanceof ErrorResponse framework) {
            HttpStatus status = HttpStatus.resolve(framework.getStatusCode().value());
            if (status != null && status.is4xxClientError()) return problem(status, status.getReasonPhrase(), "The request could not be completed.");
        }
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected error", "The request could not be completed safely.");
    }

    private ResponseEntity<ProblemDetail> problem(HttpStatus status, String title, String detail) {
        return ResponseEntity.status(status).body(problemBody(status, title, detail));
    }

    private ProblemDetail problemBody(HttpStatus status, String title, String detail) {
        ProblemDetail body = ProblemDetail.forStatusAndDetail(status, detail);
        body.setTitle(title);
        body.setType(URI.create("about:blank"));
        return body;
    }
}
