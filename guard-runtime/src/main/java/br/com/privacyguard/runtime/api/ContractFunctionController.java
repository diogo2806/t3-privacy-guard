package br.com.privacyguard.runtime.api;

import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.CallerRegistry;
import br.com.privacyguard.runtime.caller.GuardFunction;
import br.com.privacyguard.runtime.policy.InvalidContractInputException;
import br.com.privacyguard.runtime.policy.PolicyDecision;
import br.com.privacyguard.runtime.policy.PolicyEvaluationRequest;
import br.com.privacyguard.runtime.policy.PolicyEvaluator;
import br.com.privacyguard.runtime.store.PolicyStore;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** HTTP face of the former contract functions; one endpoint per WIT export. */
@RestController
@RequestMapping("/v1/functions")
public class ContractFunctionController {
    static final int MAX_INPUT_BYTES = 64 * 1024;

    private final CallerRegistry callers;
    private final PolicyStore policies;

    public ContractFunctionController(CallerRegistry callers, PolicyStore policies) {
        this.callers = callers;
        this.policies = policies;
    }

    @PostMapping(path = "/evaluate-action", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> evaluateAction(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        HttpServletRequest request
    ) throws IOException {
        Optional<Caller> caller = callers.authenticate(bearerToken(authorization));
        if (caller.isEmpty()) return error(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED");
        if (!caller.get().mayCall(GuardFunction.EVALUATE_ACTION)) return error(HttpStatus.FORBIDDEN, "FUNCTION_NOT_GRANTED");

        byte[] input = request.getInputStream().readNBytes(MAX_INPUT_BYTES + 1);
        if (input.length > MAX_INPUT_BYTES) return error(HttpStatus.PAYLOAD_TOO_LARGE, "INPUT_TOO_LARGE");

        PolicyEvaluationRequest parsed;
        try {
            parsed = PolicyEvaluator.parseRequest(input);
        } catch (InvalidContractInputException ex) {
            return error(HttpStatus.BAD_REQUEST, "INVALID_INPUT");
        }
        PolicyDecision decision = PolicyEvaluator.evaluate(parsed, policies.current(), caller.get()::isAgent);
        return ResponseEntity.ok(decision);
    }

    private static String bearerToken(String authorization) {
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) return null;
        return authorization.substring(7).trim();
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code) {
        return ResponseEntity.status(status).body(Map.of("error", code));
    }
}
