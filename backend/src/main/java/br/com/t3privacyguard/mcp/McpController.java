package br.com.t3privacyguard.mcp;

import br.com.t3privacyguard.integration.RuntimePolicyClient;
import br.com.t3privacyguard.integration.RuntimePolicyClient.EvaluationRequest;
import br.com.t3privacyguard.integration.RuntimeRemediationClient;
import br.com.t3privacyguard.integration.RuntimeStatusClient;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Model Context Protocol endpoint (Streamable HTTP, stateless, JSON responses) so a company's existing agent can ask
 * the guard before acting. It exposes evaluation and independent read-back only: authorizing and executing a
 * remediation always need the human flow in the dashboard.
 */
@RestController
@RequestMapping("/mcp")
public class McpController {
    static final List<String> SUPPORTED_PROTOCOL_VERSIONS = List.of("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05");
    private static final String FAILED_CLOSED = "Privacy Guard MCP operation failed closed";
    private static final int INVALID_REQUEST = -32600;
    private static final int METHOD_NOT_FOUND = -32601;
    private static final int INVALID_PARAMS = -32602;

    private final RuntimeStatusClient status;
    private final RuntimePolicyClient policy;
    private final RuntimeRemediationClient remediation;
    private final ObjectMapper mapper;
    private final Map<String, Function<JsonNode, Object>> tools;

    public McpController(RuntimeStatusClient status, RuntimePolicyClient policy, RuntimeRemediationClient remediation, ObjectMapper mapper) {
        this.status = status;
        this.policy = policy;
        this.remediation = remediation;
        this.mapper = mapper;
        this.tools = Map.of(
            "privacy.contract_identity", this::contractIdentity,
            "privacy.evaluate_action", this::evaluateAction,
            "privacy.verify_remediation", this::verifyRemediation
        );
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<JsonNode> handle(@RequestBody JsonNode message) {
        if (message.isArray()) {
            ArrayNode responses = mapper.createArrayNode();
            for (JsonNode item : message) {
                JsonNode response = dispatch(item);
                if (response != null) responses.add(response);
            }
            return responses.isEmpty() ? ResponseEntity.accepted().build() : ResponseEntity.ok(responses);
        }
        JsonNode response = dispatch(message);
        return response == null ? ResponseEntity.accepted().build() : ResponseEntity.ok(response);
    }

    /** No server-initiated stream and no sessions in this stateless server. */
    @GetMapping
    public ResponseEntity<Void> stream() {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).build();
    }

    @DeleteMapping
    public ResponseEntity<Void> endSession() {
        return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).build();
    }

    private JsonNode dispatch(JsonNode message) {
        if (!message.isObject() || !"2.0".equals(message.path("jsonrpc").asText())) return error(null, INVALID_REQUEST, "Invalid Request");
        JsonNode id = message.get("id");
        if (id == null) return null;
        String method = message.path("method").asText("");
        JsonNode params = message.path("params");
        return switch (method) {
            case "initialize" -> result(id, initialize(params));
            case "ping" -> result(id, mapper.createObjectNode());
            case "tools/list" -> result(id, toolList());
            case "tools/call" -> callTool(id, params);
            default -> error(id, METHOD_NOT_FOUND, "Method not found");
        };
    }

    private ObjectNode initialize(JsonNode params) {
        String requested = params.path("protocolVersion").asText("");
        ObjectNode result = mapper.createObjectNode();
        result.put("protocolVersion", SUPPORTED_PROTOCOL_VERSIONS.contains(requested) ? requested : SUPPORTED_PROTOCOL_VERSIONS.get(0));
        result.putObject("capabilities").putObject("tools").put("listChanged", false);
        result.putObject("serverInfo").put("name", "privacy-guard").put("version", "0.3.0");
        result.put("instructions", "Ask privacy.evaluate_action before acting on sensitive data or systems. ALLOW is not authorization: "
            + "remediation still requires human approval in Privacy Guard.");
        return result;
    }

    private ObjectNode toolList() {
        ObjectNode result = mapper.createObjectNode();
        ArrayNode list = result.putArray("tools");

        ObjectNode identity = tool(list, "privacy.contract_identity", "Return the trust runtime's contract id and version.");
        identity.putObject("properties");

        ObjectNode evaluate = tool(list, "privacy.evaluate_action",
            "Evaluate an AI-proposed action under the active versioned privacy policy. This tool never authorizes remediation.");
        ObjectNode properties = evaluate.putObject("properties");
        string(properties, "request_id", 128);
        string(properties, "action", 80);
        string(properties, "resource", 256);
        string(properties, "purpose", 80);
        string(properties, "host", 253);
        array(properties, "fields", 64);
        array(properties, "private_refs", 8);
        evaluate.putArray("required").add("request_id").add("action").add("resource").add("purpose").add("fields");

        ObjectNode verify = tool(list, "privacy.verify_remediation",
            "Independently read back an already accepted remediation. This tool cannot execute or authorize remediation.");
        ObjectNode verifyProperties = verify.putObject("properties");
        string(verifyProperties, "request_id", 128);
        string(verifyProperties, "operation_id", 128);
        verifyProperties.putObject("action").put("type", "string").putArray("enum").add("revoke-credential").add("notify-security");
        verifyProperties.putObject("expected_state").put("type", "string").putArray("enum").add("REVOKED").add("DELIVERED");
        verify.putArray("required").add("request_id").add("operation_id").add("action").add("expected_state");
        return result;
    }

    private ObjectNode tool(ArrayNode list, String name, String description) {
        ObjectNode tool = list.addObject().put("name", name).put("description", description);
        ObjectNode schema = tool.putObject("inputSchema").put("type", "object").put("additionalProperties", false);
        return schema;
    }

    private static void string(ObjectNode properties, String name, int maxLength) {
        properties.putObject(name).put("type", "string").put("minLength", 1).put("maxLength", maxLength);
    }

    private static void array(ObjectNode properties, String name, int maxItems) {
        properties.putObject(name).put("type", "array").put("maxItems", maxItems)
            .putObject("items").put("type", "string").put("minLength", 1).put("maxLength", 80);
    }

    private JsonNode callTool(JsonNode id, JsonNode params) {
        String name = params.path("name").asText("");
        Function<JsonNode, Object> tool = tools.get(name);
        if (tool == null) return error(id, INVALID_PARAMS, "Unknown tool: " + name);
        JsonNode arguments = params.has("arguments") ? params.get("arguments") : mapper.createObjectNode();
        Object output;
        try {
            output = tool.apply(arguments);
        } catch (InvalidToolArgumentsException ex) {
            return error(id, INVALID_PARAMS, "Invalid arguments for " + name);
        } catch (RuntimeException ex) {
            return result(id, toolResult(FAILED_CLOSED, true));
        }
        try {
            return result(id, toolResult(mapper.writeValueAsString(output), false));
        } catch (Exception ex) {
            return result(id, toolResult(FAILED_CLOSED, true));
        }
    }

    private Object contractIdentity(JsonNode arguments) {
        requireOnly(arguments, Set.of());
        return status.contractIdentity().orElseThrow(() -> new IllegalStateException("contract identity unavailable"));
    }

    private Object evaluateAction(JsonNode arguments) {
        requireOnly(arguments, Set.of("request_id", "action", "resource", "purpose", "host", "fields", "private_refs"));
        return policy.evaluate(new EvaluationRequest(
            text(arguments, "request_id", 128, true),
            text(arguments, "action", 80, true),
            text(arguments, "resource", 256, true),
            text(arguments, "purpose", 80, true),
            text(arguments, "host", 253, false),
            texts(arguments, "fields", 64, true),
            texts(arguments, "private_refs", 8, false)
        ));
    }

    private Object verifyRemediation(JsonNode arguments) {
        requireOnly(arguments, Set.of("request_id", "operation_id", "action", "expected_state"));
        String requestId = text(arguments, "request_id", 128, true);
        String operationId = text(arguments, "operation_id", 128, true);
        String action = text(arguments, "action", 80, true);
        String expectedState = text(arguments, "expected_state", 32, true);
        if (action.equals("revoke-credential") && expectedState.equals("REVOKED")) return remediation.verify(requestId, operationId);
        if (action.equals("notify-security") && expectedState.equals("DELIVERED")) return remediation.verifyDelivery(requestId, operationId);
        throw new InvalidToolArgumentsException();
    }

    private static void requireOnly(JsonNode arguments, Set<String> allowed) {
        if (!arguments.isObject()) throw new InvalidToolArgumentsException();
        Iterator<String> names = arguments.fieldNames();
        while (names.hasNext()) if (!allowed.contains(names.next())) throw new InvalidToolArgumentsException();
    }

    private static String text(JsonNode arguments, String field, int maxLength, boolean required) {
        JsonNode value = arguments.get(field);
        if (value == null || value.isNull()) {
            if (required) throw new InvalidToolArgumentsException();
            return null;
        }
        if (!value.isTextual() || value.asText().isEmpty() || value.asText().length() > maxLength) throw new InvalidToolArgumentsException();
        return value.asText();
    }

    private static List<String> texts(JsonNode arguments, String field, int maxItems, boolean required) {
        JsonNode value = arguments.get(field);
        if (value == null || value.isNull()) {
            if (required) throw new InvalidToolArgumentsException();
            return List.of();
        }
        if (!value.isArray() || value.size() > maxItems) throw new InvalidToolArgumentsException();
        List<String> result = new ArrayList<>();
        for (JsonNode item : value) {
            if (!item.isTextual() || item.asText().isEmpty() || item.asText().length() > 80) throw new InvalidToolArgumentsException();
            result.add(item.asText());
        }
        return List.copyOf(result);
    }

    private ObjectNode toolResult(String text, boolean isError) {
        ObjectNode result = mapper.createObjectNode();
        result.putArray("content").addObject().put("type", "text").put("text", text);
        if (isError) result.put("isError", true);
        return result;
    }

    private ObjectNode result(JsonNode id, JsonNode result) {
        ObjectNode response = mapper.createObjectNode().put("jsonrpc", "2.0");
        response.set("id", id);
        response.set("result", result);
        return response;
    }

    private ObjectNode error(JsonNode id, int code, String message) {
        ObjectNode response = mapper.createObjectNode().put("jsonrpc", "2.0");
        response.set("id", id);
        response.putObject("error").put("code", code).put("message", message);
        return response;
    }

    private static final class InvalidToolArgumentsException extends RuntimeException {}
}
