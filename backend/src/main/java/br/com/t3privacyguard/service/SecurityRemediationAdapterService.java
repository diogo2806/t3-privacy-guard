package br.com.t3privacyguard.service;

import br.com.t3privacyguard.persistence.SecurityRemediationOperationEntity;
import br.com.t3privacyguard.persistence.SecurityRemediationOperationRepository;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class SecurityRemediationAdapterService {
    private static final Set<String> REVOKE_FIELDS = Set.of(
        "request_id", "action", "resource", "purpose",
        "incident_id", "credential_id", "reason"
    );
    private static final Set<String> NOTIFY_FIELDS = Set.of(
        "request_id", "action", "resource", "purpose",
        "incident_id", "severity", "summary", "recipient"
    );
    private static final Pattern REQUEST_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final Pattern OPERATION_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final String MUST_EGRESS_SENTINEL = "SENTINEL_MUST_EGRESS";
    private static final String MUST_NOT_EGRESS_SENTINEL = "SENTINEL_MUST_NOT_EGRESS";

    private final SecurityRemediationOperationRepository operations;

    public SecurityRemediationAdapterService(SecurityRemediationOperationRepository operations) {
        this.operations = operations;
    }

    public ExecutionResult execute(String idempotencyKey, JsonNode body) {
        String requestId = requireSafeRequestId(idempotencyKey);
        ActionContract contract = validateExecutionBody(body, requestId);

        var existing = operations.findByRequestId(requestId);
        if (existing.isPresent()) return idempotentResult(existing.get(), contract.action());

        Instant now = Instant.now();
        var operation = new SecurityRemediationOperationEntity(
            "op_" + UUID.randomUUID().toString().replace("-", ""),
            requestId,
            contract.action(),
            contract.expectedState(),
            contract.recipientResolved(),
            containsValue(body, MUST_EGRESS_SENTINEL),
            containsValue(body, MUST_NOT_EGRESS_SENTINEL),
            now
        );
        try {
            operations.saveAndFlush(operation);
            return new ExecutionResult(operation.getOperationId());
        } catch (DataIntegrityViolationException conflict) {
            SecurityRemediationOperationEntity raced = operations.findByRequestId(requestId)
                .orElseThrow(() -> conflict);
            return idempotentResult(raced, contract.action());
        }
    }

    public VerificationResult verify(JsonNode body) {
        VerificationRequest request = validateVerificationBody(body);
        SecurityRemediationOperationEntity operation = operations.findById(request.operationId())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Remediation operation not found"));

        if (!operation.getRequestId().equals(request.requestId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Remediation request does not match the operation");
        }
        if (!operation.getAction().equals(request.action())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Remediation action does not match the operation");
        }
        if (!operation.getState().equals(request.expectedState())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Remediation expected state does not match the operation");
        }

        Boolean recipientResolved = "notify-security".equals(operation.getAction()) ? operation.isRecipientResolved() : null;
        return new VerificationResult(
            operation.getOperationId(),
            operation.getState(),
            recipientResolved,
            new PayloadProof(operation.isMustEgressSeen(), operation.isMustNotEgressSeen())
        );
    }

    private ExecutionResult idempotentResult(SecurityRemediationOperationEntity operation, String action) {
        if (!operation.getAction().equals(action)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency key is already bound to another remediation action");
        }
        return new ExecutionResult(operation.getOperationId());
    }

    private static ActionContract validateExecutionBody(JsonNode body, String idempotencyKey) {
        if (body == null || !body.isObject()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Remediation body must be a JSON object");
        }

        Set<String> fields = new HashSet<>();
        Iterator<Map.Entry<String, JsonNode>> entries = body.fields();
        while (entries.hasNext()) {
            Map.Entry<String, JsonNode> entry = entries.next();
            fields.add(entry.getKey());
            requireText(entry.getValue(), entry.getKey(), maxLength(entry.getKey()));
        }

        String requestId = requireText(body.get("request_id"), "request_id", 128);
        if (!REQUEST_ID.matcher(requestId).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Remediation request_id is invalid");
        }
        if (!idempotencyKey.equals(requestId)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Idempotency-Key does not match remediation request_id");
        }

        String action = requireText(body.get("action"), "action", 32);
        String purpose = requireText(body.get("purpose"), "purpose", 64);
        requireText(body.get("resource"), "resource", 512);

        if ("revoke-credential".equals(action)) {
            if (!fields.equals(REVOKE_FIELDS) || !"incident-remediation".equals(purpose)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Remediation body does not match the revoke-credential execution contract");
            }
            return new ActionContract(action, "REVOKED", false);
        }

        if ("notify-security".equals(action)) {
            if (!fields.equals(NOTIFY_FIELDS) || !"incident-notification".equals(purpose)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Remediation body does not match the notify-security execution contract");
            }
            return new ActionContract(action, "DELIVERED", true);
        }

        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Remediation action is not supported");
    }

    private static VerificationRequest validateVerificationBody(JsonNode body) {
        Set<String> expectedFields = Set.of("request_id", "operation_id", "action", "expected_state");
        if (body == null || !body.isObject()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification body must be a JSON object");
        }
        Set<String> fields = new HashSet<>();
        body.fieldNames().forEachRemaining(fields::add);
        if (!fields.equals(expectedFields)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification body does not match the supported contract");
        }

        String requestId = requireText(body.get("request_id"), "request_id", 128);
        String operationId = requireText(body.get("operation_id"), "operation_id", 128);
        String action = requireText(body.get("action"), "action", 32);
        String expectedState = requireText(body.get("expected_state"), "expected_state", 32);
        if (!REQUEST_ID.matcher(requestId).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification request_id is invalid");
        }
        if (!OPERATION_ID.matcher(operationId).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification operation_id is invalid");
        }
        String requiredState = switch (action) {
            case "revoke-credential" -> "REVOKED";
            case "notify-security" -> "DELIVERED";
            default -> throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification action is not supported");
        };
        if (!requiredState.equals(expectedState)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Verification expected_state does not match the remediation action");
        }
        return new VerificationRequest(requestId, operationId, action, expectedState);
    }

    private static String requireSafeRequestId(String value) {
        String normalized = value == null ? "" : value.trim();
        if (!REQUEST_ID.matcher(normalized).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Idempotency-Key is required and must be a safe opaque identifier");
        }
        return normalized;
    }

    private static String requireText(JsonNode value, String field, int maxLength) {
        if (value == null || !value.isTextual()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Remediation field " + field + " must be text");
        }
        String normalized = value.asText().trim();
        if (normalized.isEmpty() || normalized.length() > maxLength) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Remediation field " + field + " is missing or too long");
        }
        return normalized;
    }

    private static int maxLength(String field) {
        return switch (field) {
            case "request_id", "incident_id", "credential_id" -> 128;
            case "action", "severity" -> 32;
            case "purpose" -> 64;
            case "reason", "recipient", "resource" -> 512;
            case "summary" -> 1024;
            default -> 512;
        };
    }

    private static boolean containsValue(JsonNode body, String expected) {
        Iterator<JsonNode> values = body.elements();
        while (values.hasNext()) {
            JsonNode value = values.next();
            if (value.isTextual() && expected.equals(value.asText())) return true;
        }
        return false;
    }

    private record ActionContract(String action, String expectedState, boolean recipientResolved) {}
    private record VerificationRequest(String requestId, String operationId, String action, String expectedState) {}

    public record ExecutionResult(@JsonProperty("operation_id") String operationId) {}

    public record PayloadProof(
        @JsonProperty("must_egress_seen") boolean mustEgressSeen,
        @JsonProperty("must_not_egress_seen") boolean mustNotEgressSeen
    ) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record VerificationResult(
        @JsonProperty("operation_id") String operationId,
        String state,
        @JsonProperty("recipient_resolved") Boolean recipientResolved,
        @JsonProperty("payload_proof") PayloadProof payloadProof
    ) {}
}
