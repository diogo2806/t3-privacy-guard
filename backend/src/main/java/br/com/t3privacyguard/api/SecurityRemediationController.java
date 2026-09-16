package br.com.t3privacyguard.api;

import br.com.t3privacyguard.service.SecurityRemediationAdapterService;
import br.com.t3privacyguard.service.SecurityRemediationAdapterService.ExecutionResult;
import br.com.t3privacyguard.service.SecurityRemediationAdapterService.VerificationResult;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/security/remediation")
public class SecurityRemediationController {
    private final SecurityRemediationAdapterService service;

    public SecurityRemediationController(SecurityRemediationAdapterService service) {
        this.service = service;
    }

    @PostMapping("/execute")
    public ResponseEntity<ExecutionResult> execute(
        @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey,
        @RequestBody JsonNode body
    ) {
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(service.execute(idempotencyKey, body));
    }

    @PostMapping("/verify")
    public VerificationResult verify(@RequestBody JsonNode body) {
        return service.verify(body);
    }
}
