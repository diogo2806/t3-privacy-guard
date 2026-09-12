package br.com.t3privacyguard.api;

import br.com.t3privacyguard.integration.GatewayUnavailableException;
import br.com.t3privacyguard.security.TooManyLoginAttemptsException;
import br.com.t3privacyguard.service.*;
import java.net.URI;
import org.springframework.http.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(IncidentNotFoundException.class)
    ResponseEntity<ProblemDetail> notFound(IncidentNotFoundException ex) { return problem(HttpStatus.NOT_FOUND, "Resource not found", ex.getMessage()); }

    @ExceptionHandler(EvidenceNotFoundException.class)
    ResponseEntity<ProblemDetail> evidenceNotFound(EvidenceNotFoundException ex) { return problem(HttpStatus.NOT_FOUND, "Evidence not available", ex.getMessage()); }

    @ExceptionHandler(ConflictException.class)
    ResponseEntity<ProblemDetail> conflict(ConflictException ex) { return problem(HttpStatus.CONFLICT, "Request conflict", ex.getMessage()); }

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

    @ExceptionHandler(GatewayUnavailableException.class)
    ResponseEntity<ProblemDetail> gateway(GatewayUnavailableException ex) { return problem(HttpStatus.SERVICE_UNAVAILABLE, "T3N policy service unavailable", "The action was not authorized because policy evaluation could not be completed."); }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<ProblemDetail> validation(MethodArgumentNotValidException ex) { return problem(HttpStatus.BAD_REQUEST, "Invalid request", "One or more request fields are invalid."); }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ProblemDetail> unexpected(Exception ex) { return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Unexpected error", "The request could not be completed safely."); }

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
