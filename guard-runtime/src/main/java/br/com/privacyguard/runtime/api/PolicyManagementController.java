package br.com.privacyguard.runtime.api;

import br.com.privacyguard.runtime.activity.ActivityLog;
import br.com.privacyguard.runtime.activity.ActivityLog.Outcome;
import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.CallerRegistry;
import br.com.privacyguard.runtime.caller.GuardFunction;
import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.contract.StrictJson;
import br.com.privacyguard.runtime.policy.AppliedPolicy;
import br.com.privacyguard.runtime.policy.PolicyDocumentException;
import br.com.privacyguard.runtime.policy.PolicyDocumentParser;
import br.com.privacyguard.runtime.store.ManagedPolicyStore;
import br.com.privacyguard.runtime.store.ManagedPolicyStore.Change;
import br.com.privacyguard.runtime.store.ManagedPolicyStore.HistoryEntry;
import br.com.privacyguard.runtime.store.ManagedPolicyStore.PolicyChangeException;
import br.com.privacyguard.runtime.store.PolicyStore;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Policy administration for callers granted manage-policy: read the current policy, its versions and history,
 * validate a candidate, publish a new version and roll back. Publishing and rollback land in the activity log; the
 * details (which version, requested by whom) are in the policy history. With a file-only policy store every write
 * answers 409 POLICY_MANAGEMENT_DISABLED.
 */
@RestController
@RequestMapping("/v1/policy")
public class PolicyManagementController {
    private static final Pattern REQUESTED_BY = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}");
    private static final Pattern POLICY_HASH = Pattern.compile("[a-f0-9]{64}");
    private static final int MAX_HISTORY_LIMIT = 200;
    private static final Set<String> VALIDATE_FIELDS = Set.of("document");
    private static final Set<String> PUBLISH_FIELDS = Set.of("document", "expected_current_hash", "requested_by");
    private static final Set<String> ROLLBACK_FIELDS = Set.of("version", "expected_current_hash", "requested_by");

    private final CallerRegistry callers;
    private final PolicyStore policies;
    private final ActivityLog activity;
    private final ObjectMapper mapper;

    public PolicyManagementController(CallerRegistry callers, PolicyStore policies, ActivityLog activity, ObjectMapper mapper) {
        this.callers = callers;
        this.policies = policies;
        this.activity = activity;
        this.mapper = mapper;
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> current(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        Optional<ResponseEntity<?>> denied = authorize(authorization).refusal();
        if (denied.isPresent()) return denied.get();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("managed", policies instanceof ManagedPolicyStore);
        Optional<byte[]> bytes = policies.current();
        if (bytes.isEmpty()) {
            body.put("state", "UNAVAILABLE");
            return ResponseEntity.ok(body);
        }
        try {
            AppliedPolicy policy = PolicyDocumentParser.parse(bytes.get());
            body.put("state", "AVAILABLE");
            body.putAll(policyBody(policy));
        } catch (PolicyDocumentException ex) {
            body.put("state", "INVALID");
            body.put("reason", ex.getMessage());
        }
        return ResponseEntity.ok(body);
    }

    @GetMapping(path = "/history", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> history(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        @RequestParam(required = false, defaultValue = "50") int limit
    ) {
        Optional<ResponseEntity<?>> denied = authorize(authorization).refusal();
        if (denied.isPresent()) return denied.get();
        if (!(policies instanceof ManagedPolicyStore managed)) return managementDisabled();
        if (limit < 1 || limit > MAX_HISTORY_LIMIT) return ContractFunctionController.error(HttpStatus.BAD_REQUEST, "INVALID_QUERY");
        List<HistoryEntry> entries = managed.history();
        List<Map<String, Object>> newestFirst = new ArrayList<>();
        for (int index = entries.size() - 1; index >= 0 && newestFirst.size() < limit; index--) {
            newestFirst.add(historyBody(entries.get(index)));
        }
        return ResponseEntity.ok(Map.of("entries", newestFirst, "total", entries.size()));
    }

    @GetMapping(path = "/versions/{version}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> version(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        @PathVariable String version
    ) {
        Optional<ResponseEntity<?>> denied = authorize(authorization).refusal();
        if (denied.isPresent()) return denied.get();
        if (!(policies instanceof ManagedPolicyStore managed)) return managementDisabled();
        return managed.version(version)
            .<ResponseEntity<?>>map(policy -> ResponseEntity.ok(policyBody(policy)))
            .orElseGet(() -> ContractFunctionController.error(HttpStatus.NOT_FOUND, PolicyChangeException.VERSION_NOT_FOUND));
    }

    @PostMapping(path = "/validate", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> validate(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        HttpServletRequest request
    ) throws IOException {
        Optional<ResponseEntity<?>> denied = authorize(authorization).refusal();
        if (denied.isPresent()) return denied.get();
        try {
            ObjectNode body = readBody(request, VALIDATE_FIELDS);
            AppliedPolicy policy = PolicyDocumentParser.parse(documentBytes(body));
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("valid", true);
            result.putAll(policyBody(policy));
            return ResponseEntity.ok(result);
        } catch (PolicyDocumentException ex) {
            return ResponseEntity.ok(Map.of("valid", false, "reason", ex.getMessage()));
        } catch (InvalidContractInputException ex) {
            return ContractFunctionController.error(HttpStatus.BAD_REQUEST, "INVALID_INPUT");
        }
    }

    @PostMapping(path = "/publish", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> publish(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        HttpServletRequest request
    ) throws IOException {
        return change(authorization, request, PUBLISH_FIELDS, (managed, caller, body) -> managed.publish(
            documentBytes(body), expectedHash(body), caller.id(), requestedBy(body)));
    }

    @PostMapping(path = "/rollback", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> rollback(
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
        HttpServletRequest request
    ) throws IOException {
        return change(authorization, request, ROLLBACK_FIELDS, (managed, caller, body) -> managed.rollback(
            StrictJson.requiredString(body, "version"), expectedHash(body), caller.id(), requestedBy(body)));
    }

    private ResponseEntity<?> change(String authorization, HttpServletRequest request, Set<String> fields, PolicyOperation operation) throws IOException {
        Authorization auth = authorize(authorization);
        if (auth.caller() == null) return auth.refusal().orElseThrow();
        Caller caller = auth.caller();
        if (auth.refusal().isPresent()) {
            return ContractFunctionController.recorded(activity, caller, GuardFunction.MANAGE_POLICY, Outcome.DENIED, auth.refusal().get());
        }
        if (!(policies instanceof ManagedPolicyStore managed)) {
            return ContractFunctionController.recorded(activity, caller, GuardFunction.MANAGE_POLICY, Outcome.ERROR, managementDisabled());
        }
        ResponseEntity<?> response;
        Outcome outcome = Outcome.ERROR;
        try {
            Change change = operation.apply(managed, caller, readBody(request, fields));
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("changed", change.changed());
            body.put("version", change.version());
            body.put("hash", change.hash());
            body.put("previous_version", change.previousVersion());
            body.put("previous_hash", change.previousHash());
            response = ResponseEntity.ok(body);
            outcome = Outcome.SUCCESS;
        } catch (InvalidContractInputException ex) {
            response = ContractFunctionController.error(HttpStatus.BAD_REQUEST, "INVALID_INPUT");
        } catch (PolicyChangeException ex) {
            response = switch (ex.code()) {
                case PolicyChangeException.POLICY_INVALID ->
                    ResponseEntity.unprocessableEntity().body(Map.of("error", ex.code(), "reason", ex.getMessage()));
                case PolicyChangeException.VERSION_NOT_FOUND -> ContractFunctionController.error(HttpStatus.NOT_FOUND, ex.code());
                default -> ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("error", ex.code(), "reason", ex.getMessage()));
            };
        } catch (UncheckedIOException ex) {
            response = ContractFunctionController.error(HttpStatus.SERVICE_UNAVAILABLE, "POLICY_STORE_UNAVAILABLE");
        }
        return ContractFunctionController.recorded(activity, caller, GuardFunction.MANAGE_POLICY, outcome, response);
    }

    private Authorization authorize(String authorization) {
        Optional<Caller> caller = callers.authenticate(ContractFunctionController.bearerToken(authorization));
        if (caller.isEmpty()) {
            return new Authorization(null, Optional.of(ContractFunctionController.error(HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED")));
        }
        if (!caller.get().mayCall(GuardFunction.MANAGE_POLICY)) {
            return new Authorization(caller.get(), Optional.of(ContractFunctionController.error(HttpStatus.FORBIDDEN, "FUNCTION_NOT_GRANTED")));
        }
        return new Authorization(caller.get(), Optional.empty());
    }

    private ObjectNode readBody(HttpServletRequest request, Set<String> fields) throws IOException {
        byte[] input = request.getInputStream().readNBytes(ContractFunctionController.MAX_INPUT_BYTES + 1);
        if (input.length > ContractFunctionController.MAX_INPUT_BYTES) throw new InvalidContractInputException("input is too large");
        ObjectNode body = StrictJson.parseObject(input);
        StrictJson.rejectUnknownFields(body, fields);
        return body;
    }

    private byte[] documentBytes(ObjectNode body) {
        try {
            return mapper.writeValueAsBytes(StrictJson.requiredObject(body, "document"));
        } catch (JsonProcessingException ex) {
            throw new InvalidContractInputException("document could not be read");
        }
    }

    private static String expectedHash(ObjectNode body) {
        String hash = StrictJson.optionalString(body, "expected_current_hash");
        if (hash != null && !POLICY_HASH.matcher(hash).matches()) throw new InvalidContractInputException("expected_current_hash is invalid");
        return hash;
    }

    private static String requestedBy(ObjectNode body) {
        String value = StrictJson.optionalString(body, "requested_by");
        if (value != null && !REQUESTED_BY.matcher(value).matches()) throw new InvalidContractInputException("requested_by is invalid");
        return value;
    }

    private Map<String, Object> policyBody(AppliedPolicy policy) {
        JsonNode document;
        try {
            document = mapper.readTree(PolicyDocumentParser.canonicalBytes(policy.document()));
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("version", policy.version());
        body.put("hash", policy.hash());
        body.put("document", document);
        return body;
    }

    private static Map<String, Object> historyBody(HistoryEntry entry) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sequence", entry.sequence());
        body.put("operation", entry.operation());
        body.put("version", entry.version());
        body.put("hash", entry.policyHash());
        body.put("previous_version", entry.previousVersion());
        body.put("previous_hash", entry.previousPolicyHash());
        body.put("caller", entry.caller());
        body.put("requested_by", entry.requestedBy());
        body.put("timestamp", Instant.ofEpochMilli(entry.timestampMs()).toString());
        body.put("entry_hash", entry.entryHash());
        return body;
    }

    private static ResponseEntity<Map<String, String>> managementDisabled() {
        return ContractFunctionController.error(HttpStatus.CONFLICT, "POLICY_MANAGEMENT_DISABLED");
    }

    private record Authorization(Caller caller, Optional<ResponseEntity<?>> refusal) {}

    @FunctionalInterface
    private interface PolicyOperation {
        Change apply(ManagedPolicyStore managed, Caller caller, ObjectNode body);
    }
}
