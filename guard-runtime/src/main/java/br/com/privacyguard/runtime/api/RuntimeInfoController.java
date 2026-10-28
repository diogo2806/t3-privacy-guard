package br.com.privacyguard.runtime.api;

import br.com.privacyguard.runtime.activity.ActivityLog;
import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.CallerRegistry;
import br.com.privacyguard.runtime.caller.GuardFunction;
import br.com.privacyguard.runtime.status.RuntimeReadinessService;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Control-plane reads for authenticated callers: who am I and what was I granted (the effective-access check that
 * T3N's checkDelegation answered), integration readiness, and the activity log.
 */
@RestController
@RequestMapping("/v1")
public class RuntimeInfoController {
    private static final int MAX_ACTIVITY_LIMIT = 200;

    private final CallerRegistry callers;
    private final RuntimeReadinessService readiness;
    private final ActivityLog activity;

    public RuntimeInfoController(CallerRegistry callers, RuntimeReadinessService readiness, ActivityLog activity) {
        this.callers = callers;
        this.readiness = readiness;
        this.activity = activity;
    }

    @GetMapping("/caller")
    public ResponseEntity<?> caller(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        Optional<Caller> caller = callers.authenticate(ContractFunctionController.bearerToken(authorization));
        if (caller.isEmpty()) return ContractFunctionController.error(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED");
        return ResponseEntity.ok(Map.of(
            "id", caller.get().id(),
            "functions", caller.get().functions().stream().map(GuardFunction::wireName).sorted().toList()
        ));
    }

    @GetMapping("/readiness")
    public ResponseEntity<?> readiness(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (callers.authenticate(ContractFunctionController.bearerToken(authorization)).isEmpty()) {
            return ContractFunctionController.error(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED");
        }
        return ResponseEntity.ok(readiness.readiness());
    }

    @GetMapping("/activity")
    public ResponseEntity<?> activity(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        @RequestParam(required = false) Long beforeSeq,
        @RequestParam(required = false) Long fromMs,
        @RequestParam(required = false) Long toMs,
        @RequestParam(required = false, defaultValue = "100") int limit
    ) {
        if (callers.authenticate(ContractFunctionController.bearerToken(authorization)).isEmpty()) {
            return ContractFunctionController.error(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED");
        }
        boolean invalid = limit < 1 || limit > MAX_ACTIVITY_LIMIT
            || (beforeSeq != null && beforeSeq < 0) || (fromMs != null && fromMs < 0) || (toMs != null && toMs < 0)
            || (fromMs != null && toMs != null && fromMs > toMs);
        if (invalid) return ContractFunctionController.error(HttpStatus.BAD_REQUEST, "INVALID_QUERY");
        return ResponseEntity.ok(activity.read(beforeSeq, fromMs, toMs, limit));
    }
}
