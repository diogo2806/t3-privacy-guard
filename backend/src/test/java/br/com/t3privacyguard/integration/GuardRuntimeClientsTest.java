package br.com.t3privacyguard.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.integration.RuntimePolicyClient.EvaluationRequest;
import br.com.t3privacyguard.integration.RuntimeRemediationClient.RemediationRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The backend's guard-runtime clients against a stand-in runtime speaking guard-runtime's HTTP contract. */
class GuardRuntimeClientsTest {
    private static final String PROPOSAL_TOKEN = "test-runtime-proposal-token-1234567890";
    private static final String EXECUTOR_TOKEN = "test-runtime-executor-token-1234567890";
    private static final String ACTIVITY_HASH = "c".repeat(64);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String READINESS = """
        {"contract_id":"guard-runtime","contract_version":"1.0.0","tenant_id":"acme","policy_state":"AVAILABLE",
         "policy_version":"2026-10-28.1","policy_hash":"%s",
         "policy_document":{"version":"2026-10-28.1","actions":{
           "create-incident":{"purpose":"incident-recording","allowed_fields":["incident_id"],"allowed_hosts":[],"allowed_private_refs":[],"requires_host":false,"requires_human_authorization":false},
           "notify-security":{"purpose":"incident-notification","allowed_fields":["incident_id"],"allowed_hosts":["security.example"],"allowed_private_refs":["verified_email"],"requires_host":true,"requires_human_authorization":true},
           "revoke-credential":{"purpose":"incident-remediation","allowed_fields":["incident_id"],"allowed_hosts":["security.example","other.example"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}}},
         "endpoint_configuration_valid":true,"execution_host":"security.example","verification_host":"security.example",
         "insecure_http_allowed":false,"credential_configured":true,"verification_key_configured":true,"private_profile_configured":true}
        """.formatted("b".repeat(64));

    private final List<Request> received = new ArrayList<>();
    private HttpServer server;
    private GuardRuntimeClient runtime;

    record Request(String path, String authorization, JsonNode body) {}

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::handle);
        server.start();
        runtime = client("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private static GuardRuntimeClient client(String url) {
        return new GuardRuntimeClient(MAPPER, url, "agent:proposal", PROPOSAL_TOKEN, "agent:executor", EXECUTOR_TOKEN, 2_000);
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        byte[] body = exchange.getRequestBody().readAllBytes();
        received.add(new Request(exchange.getRequestURI().toString(), authorization, body.length == 0 ? null : MAPPER.readTree(body)));
        String caller = ("Bearer " + PROPOSAL_TOKEN).equals(authorization) ? "agent:proposal"
            : ("Bearer " + EXECUTOR_TOKEN).equals(authorization) ? "agent:executor" : null;
        if (path.equals("/actuator/health")) { respond(exchange, 200, "{\"status\":\"UP\"}"); return; }
        if (caller == null) { respond(exchange, 401, "{\"error\":\"UNAUTHENTICATED\"}"); return; }
        exchange.getResponseHeaders().add("X-Activity-Sequence", "7");
        exchange.getResponseHeaders().add("X-Activity-Hash", ACTIVITY_HASH);
        JsonNode input = body.length == 0 ? null : MAPPER.readTree(body);
        switch (path) {
            case "/v1/caller" -> respond(exchange, 200, caller.equals("agent:proposal")
                ? "{\"id\":\"agent:proposal\",\"functions\":[\"evaluate-action\"]}"
                : "{\"id\":\"agent:executor\",\"functions\":[\"execute-remediation\",\"verify-remediation\"]}");
            case "/v1/readiness" -> respond(exchange, 200, READINESS);
            case "/v1/activity" -> respond(exchange, 200, "{\"events\":[{\"sequence\":7,\"hash\":\"" + ACTIVITY_HASH + "\",\"timestampMs\":1,\"callerType\":\"agent\",\"actorDid\":\"agent:proposal\",\"onBehalfOfDid\":\"acme\",\"contractId\":\"guard-runtime\",\"function\":\"evaluate-action\",\"outcome\":\"success\",\"roles\":[\"evaluate-action\"]}],\"nextSequence\":null,\"complete\":true}");
            case "/v1/functions/evaluate-action" -> respond(exchange, 200, "{\"request_id\":\"" + input.path("request_id").asText() + "\",\"decision\":\"REDACT\",\"reason_code\":\"DATA_MINIMIZATION_REQUIRED\",\"reason\":\"r\",\"allowed_fields\":[\"incident_id\"],\"redacted_fields\":[\"employee_department\"],\"allowed_private_refs\":[],\"redacted_private_refs\":[],\"policy_version\":\"2026-10-28.1\",\"policy_hash\":\"" + "b".repeat(64) + "\",\"requires_human_authorization\":true}");
            case "/v1/functions/execute-remediation" -> {
                if ("changed.example".equals(input.path("approved_host").asText())) {
                    respond(exchange, 422, "{\"error\":\"CONTRACT_REJECTED\",\"reason\":\"EXECUTION_DESTINATION_CHANGED\"}");
                } else if ("stale-policy.example".equals(input.path("approved_host").asText())) {
                    respond(exchange, 422, "{\"error\":\"CONTRACT_REJECTED\",\"reason\":\"active policy changed after authorization; remediation must be re-evaluated\"}");
                } else if ("upstream-error.example".equals(input.path("approved_host").asText())) {
                    respond(exchange, 422, "{\"error\":\"CONTRACT_REJECTED\",\"reason\":\"remediation upstream returned HTTP 500\"}");
                } else {
                    respond(exchange, 200, "{\"request_id\":\"req-1\",\"status\":\"PENDING_VERIFICATION\",\"http_code\":202,\"operation_id\":\"op-1\",\"policy_version\":\"" + input.path("policy_version").asText() + "\",\"policy_hash\":\"" + input.path("policy_hash").asText() + "\"}");
                }
            }
            case "/v1/functions/verify-remediation" -> respond(exchange, 200, "{\"request_id\":\"req-1\",\"status\":\"VERIFIED\",\"observed_state\":\"REVOKED\"}");
            default -> respond(exchange, 404, "{}");
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static RemediationRequest remediation(String approvedHost) {
        return new RemediationRequest("inc-1", "act-1", "dec-1", "req-1", "revoke-credential", "credential:cred-42", "incident-remediation",
            approvedHost, List.of("incident_id"), Map.of("incident_id", "inc-1"), List.of(), "2026-10-28.1", "b".repeat(64), "d".repeat(64), 1L);
    }

    @Test
    void evaluationRunsAsTheProposalAgentAndCarriesTheActivityReference() {
        var decision = new RuntimePolicyClient(runtime, MAPPER).evaluate(new EvaluationRequest(
            "req-1", "revoke-credential", "credential:cred-42", "incident-remediation", "security.example", List.of("incident_id"), List.of()));

        assertThat(decision.decision()).isEqualTo(DecisionType.REDACT);
        assertThat(decision.activitySequence()).isEqualTo(7L);
        assertThat(decision.activityHash()).isEqualTo(ACTIVITY_HASH);
        Request sent = received.get(0);
        assertThat(sent.authorization()).isEqualTo("Bearer " + PROPOSAL_TOKEN);
        assertThat(sent.body().path("agent_did").asText()).isEqualTo("agent:proposal");
    }

    @Test
    void remediationRunsAsTheExecutorWithTheCapabilityAndMapsDestinationChanges() {
        RuntimeRemediationClient remediation = new RuntimeRemediationClient(runtime, MAPPER);

        var result = remediation.execute(remediation("security.example"), "v2.payload.signature");
        assertThat(result.operationId()).isEqualTo("op-1");
        assertThat(result.activitySequence()).isEqualTo(7L);
        JsonNode executed = received.stream().filter(r -> r.path().startsWith("/v1/functions/execute")).findFirst().orElseThrow().body();
        assertThat(executed.path("executor_did").asText()).isEqualTo("agent:executor");
        assertThat(executed.path("agent_did").asText()).isEqualTo("agent:proposal");
        assertThat(executed.path("authorization_proof").asText()).isEqualTo("v2.payload.signature");
        assertThat(executed.has("operator_principal_hash")).isFalse();

        assertThatThrownBy(() -> remediation.execute(remediation("changed.example"), "v2.payload.signature"))
            .isInstanceOf(RemediationDestinationChangedException.class);
        assertThatThrownBy(() -> remediation.execute(remediation("stale-policy.example"), "v2.payload.signature"))
            .isInstanceOf(RemediationPolicyChangedException.class);
        // A refusal after the upstream call stays an unknown outcome: the side effect may have happened.
        assertThatThrownBy(() -> remediation.execute(remediation("upstream-error.example"), "v2.payload.signature"))
            .isInstanceOf(TrustRuntimeUnavailableException.class);
        assertThat(remediation.verify("req-1", "op-1").status()).isEqualTo("VERIFIED");
    }

    @Test
    void statusReflectsIdentitiesGrantsReadinessAndActivity() {
        RuntimeStatusClient status = new RuntimeStatusClient(runtime, MAPPER);

        assertThat(status.health()).isTrue();
        assertThat(status.tenantStatus()).hasValueSatisfying(tenant -> {
            assertThat(tenant.tenantDid()).isEqualTo("acme");
            assertThat(tenant.network()).isEqualTo("selfhosted");
        });
        assertThat(status.agentStatus().orElseThrow().agentDid()).isEqualTo("agent:proposal");
        assertThat(status.executorStatus().orElseThrow().executorDid()).isEqualTo("agent:executor");
        assertThat(status.contractIdentity().orElseThrow().contractVersion()).isEqualTo("1.0.0");
        assertThat(status.delegationStatus("guard-runtime").orElseThrow().effectiveState()).isEqualTo("ACTIVE");
        var executor = status.executorDelegationStatus("guard-runtime").orElseThrow();
        assertThat(executor.effectiveState()).isEqualTo("ACTIVE");
        assertThat(executor.allowedHosts()).containsExactly("security.example");
        var readiness = status.enterpriseIntegrationReadiness().orElseThrow();
        assertThat(readiness.state()).isEqualTo("READY");
        assertThat(readiness.evaluationOnlyActions()).containsExactly("create-incident");
        assertThat(status.activity(0, 10, 50).orElseThrow().events()).extracting(RuntimeStatusClient.ActivityEvent::function).containsExactly("evaluate-action");
    }

    @Test
    void unknownCredentialsAreReportedAsNotGranted() {
        GuardRuntimeClient wrong = new GuardRuntimeClient(MAPPER, "http://127.0.0.1:" + server.getAddress().getPort(),
            "agent:proposal", "wrong-proposal-token-1234567890123456", "agent:executor", EXECUTOR_TOKEN, 2_000);
        var proposal = new RuntimeStatusClient(wrong, MAPPER).delegationStatus("guard-runtime").orElseThrow();
        assertThat(proposal.memberState()).isEqualTo("NOT_GRANTED");
        assertThat(proposal.effectiveState()).isEqualTo("DENIED");
    }

    @Test
    void unreachableRuntimeFailsClosed() {
        server.stop(0);
        RuntimeStatusClient status = new RuntimeStatusClient(runtime, MAPPER);

        assertThat(status.health()).isFalse();
        assertThat(status.tenantStatus()).isEmpty();
        assertThat(status.delegationStatus("guard-runtime").orElseThrow().memberState()).isEqualTo("UNKNOWN");
        var readiness = status.enterpriseIntegrationReadiness().orElseThrow();
        assertThat(readiness.state()).isEqualTo("UNKNOWN");
        assertThat(readiness.diagnosticCode()).isEqualTo("TRUST_RUNTIME_UNAVAILABLE");
        assertThatThrownBy(() -> new RuntimePolicyClient(runtime, MAPPER).evaluate(new EvaluationRequest(
            "req-1", "revoke-credential", "credential:cred-42", "incident-remediation", null, List.of(), List.of())))
            .isInstanceOf(TrustRuntimeUnavailableException.class)
            .hasMessageNotContaining(PROPOSAL_TOKEN);
    }

    @Test
    void configurationRejectsSharedOrWeakCredentials() {
        assertThatThrownBy(() -> new GuardRuntimeClient(MAPPER, "http://runtime:3101", "agent:proposal", PROPOSAL_TOKEN, "agent:executor", PROPOSAL_TOKEN, 2_000))
            .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new GuardRuntimeClient(MAPPER, "http://runtime:3101", "agent:same", PROPOSAL_TOKEN, "agent:same", EXECUTOR_TOKEN, 2_000))
            .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new GuardRuntimeClient(MAPPER, "http://runtime:3101", "agent:proposal", "short", "agent:executor", EXECUTOR_TOKEN, 2_000))
            .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new GuardRuntimeClient(MAPPER, "http://user:pass@runtime:3101", "agent:proposal", PROPOSAL_TOKEN, "agent:executor", EXECUTOR_TOKEN, 2_000))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void reachesAnInternalNameWithAnUnderscoreThroughItsResolvedAddress() throws Exception {
        GuardRuntimeClient swarm = client("http://privacy_guard-runtime:" + server.getAddress().getPort());
        swarm.resolver(host -> {
            assertThat(host).isEqualTo("privacy_guard-runtime");
            return java.net.InetAddress.getByName("127.0.0.1");
        });

        assertThat(swarm.getPublic("/actuator/health").ok()).isTrue();
        assertThatThrownBy(() -> client("https://privacy_guard-runtime:3101")).isInstanceOf(IllegalStateException.class).hasMessageContaining("underscore");
        assertThatThrownBy(() -> client("http://privacy_guard-runtime")).isInstanceOf(IllegalStateException.class);
    }
}
