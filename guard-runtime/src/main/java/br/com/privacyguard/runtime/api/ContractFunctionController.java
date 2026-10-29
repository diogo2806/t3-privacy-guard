package br.com.privacyguard.runtime.api;

import br.com.privacyguard.runtime.activity.ActivityEvent;
import br.com.privacyguard.runtime.activity.ActivityLog;
import br.com.privacyguard.runtime.activity.ActivityLog.Outcome;
import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.CallerRegistry;
import br.com.privacyguard.runtime.caller.GuardFunction;
import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.policy.PolicyEvaluator;
import br.com.privacyguard.runtime.remediation.RemediationExecutionRequest;
import br.com.privacyguard.runtime.remediation.RemediationService;
import br.com.privacyguard.runtime.remediation.RemediationVerificationRequest;
import br.com.privacyguard.runtime.store.PolicyStore;
import io.micrometer.core.instrument.Metrics;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP face of the former contract functions; one endpoint per WIT export. A contract refusal is 422 with the
 * contract's message (T3N returned the same text to the caller); malformed input is 400 without detail. Every call
 * by an authenticated caller lands in the activity log, and the entry is returned in X-Activity-* headers.
 */
@RestController
@RequestMapping("/v1/functions")
public class ContractFunctionController {
    static final int MAX_INPUT_BYTES = 64 * 1024;
    static final String ACTIVITY_SEQUENCE_HEADER = "X-Activity-Sequence";
    static final String ACTIVITY_HASH_HEADER = "X-Activity-Hash";
    private static final Logger LOG = LoggerFactory.getLogger(ContractFunctionController.class);

    private final CallerRegistry callers;
    private final PolicyStore policies;
    private final RemediationService remediation;
    private final ActivityLog activity;

    public ContractFunctionController(CallerRegistry callers, PolicyStore policies, RemediationService remediation, ActivityLog activity) {
        this.callers = callers;
        this.policies = policies;
        this.remediation = remediation;
        this.activity = activity;
    }

    @PostMapping(path = "/evaluate-action", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> evaluateAction(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        HttpServletRequest request
    ) throws IOException {
        return invoke(authorization, request, GuardFunction.EVALUATE_ACTION,
            (caller, input) -> PolicyEvaluator.evaluate(PolicyEvaluator.parseRequest(input), policies.current(), caller::hasId));
    }

    @PostMapping(path = "/execute-remediation", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> executeRemediation(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        HttpServletRequest request
    ) throws IOException {
        return invoke(authorization, request, GuardFunction.EXECUTE_REMEDIATION,
            (caller, input) -> remediation.execute(RemediationExecutionRequest.parse(input), caller));
    }

    @PostMapping(path = "/verify-remediation", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> verifyRemediation(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        HttpServletRequest request
    ) throws IOException {
        return invoke(authorization, request, GuardFunction.VERIFY_REMEDIATION,
            (caller, input) -> remediation.verify(RemediationVerificationRequest.parse(input)));
    }

    private ResponseEntity<?> invoke(
        String authorization,
        HttpServletRequest request,
        GuardFunction function,
        BiFunction<Caller, byte[], Object> handler
    ) throws IOException {
        Optional<Caller> authenticated = callers.authenticate(bearerToken(authorization));
        if (authenticated.isEmpty()) return error(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED");
        Caller caller = authenticated.get();
        if (!caller.mayCall(function)) {
            return recorded(activity, caller, function, Outcome.DENIED, error(HttpStatus.FORBIDDEN, "FUNCTION_NOT_GRANTED"));
        }

        byte[] input = request.getInputStream().readNBytes(MAX_INPUT_BYTES + 1);
        if (input.length > MAX_INPUT_BYTES) {
            return recorded(activity, caller, function, Outcome.ERROR, error(HttpStatus.PAYLOAD_TOO_LARGE, "INPUT_TOO_LARGE"));
        }

        try {
            return recorded(activity, caller, function, Outcome.SUCCESS, ResponseEntity.ok(handler.apply(caller, input)));
        } catch (InvalidContractInputException ex) {
            return recorded(activity, caller, function, Outcome.ERROR, error(HttpStatus.BAD_REQUEST, "INVALID_INPUT"));
        } catch (ContractRejectedException ex) {
            return recorded(activity, caller, function, Outcome.ERROR,
                ResponseEntity.unprocessableEntity().body(Map.of("error", "CONTRACT_REJECTED", "reason", ex.getMessage())));
        }
    }

    /**
     * An audit write failure must not hide the result of a side effect that already happened; the missing entry
     * shows up in the backend's reconciliation as a local-only event instead.
     */
    static ResponseEntity<?> recorded(ActivityLog activity, Caller caller, GuardFunction function, Outcome outcome, ResponseEntity<?> response) {
        Metrics.counter("guard_runtime.calls", "function", function.wireName(), "outcome", outcome.wireName()).increment();
        ActivityEvent event;
        try {
            event = activity.append(caller, function, outcome);
        } catch (UncheckedIOException ex) {
            LOG.error("Activity log append failed for {} {}", function.wireName(), outcome.wireName());
            return response;
        }
        return ResponseEntity.status(response.getStatusCode())
            .header(ACTIVITY_SEQUENCE_HEADER, Long.toString(event.sequence()))
            .header(ACTIVITY_HASH_HEADER, event.hash())
            .body(response.getBody());
    }

    static String bearerToken(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        return authorization.substring(7).trim();
    }

    static ResponseEntity<Map<String, String>> error(HttpStatus status, String code) {
        return ResponseEntity.status(status).body(Map.of("error", code));
    }
}
