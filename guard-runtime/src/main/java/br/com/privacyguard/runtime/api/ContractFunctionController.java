package br.com.privacyguard.runtime.api;

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
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiFunction;
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
 * contract's message (T3N returned the same text to the caller); malformed input is 400 without detail.
 */
@RestController
@RequestMapping("/v1/functions")
public class ContractFunctionController {
    static final int MAX_INPUT_BYTES = 64 * 1024;

    private final CallerRegistry callers;
    private final PolicyStore policies;
    private final RemediationService remediation;

    public ContractFunctionController(CallerRegistry callers, PolicyStore policies, RemediationService remediation) {
        this.callers = callers;
        this.policies = policies;
        this.remediation = remediation;
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
        Optional<Caller> caller = callers.authenticate(bearerToken(authorization));
        if (caller.isEmpty()) return error(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED");
        if (!caller.get().mayCall(function)) return error(HttpStatus.FORBIDDEN, "FUNCTION_NOT_GRANTED");

        byte[] input = request.getInputStream().readNBytes(MAX_INPUT_BYTES + 1);
        if (input.length > MAX_INPUT_BYTES) return error(HttpStatus.PAYLOAD_TOO_LARGE, "INPUT_TOO_LARGE");

        try {
            return ResponseEntity.ok(handler.apply(caller.get(), input));
        } catch (InvalidContractInputException ex) {
            return error(HttpStatus.BAD_REQUEST, "INVALID_INPUT");
        } catch (ContractRejectedException ex) {
            return ResponseEntity.unprocessableEntity().body(Map.of("error", "CONTRACT_REJECTED", "reason", ex.getMessage()));
        }
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        return authorization.substring(7).trim();
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code) {
        return ResponseEntity.status(status).body(Map.of("error", code));
    }
}
