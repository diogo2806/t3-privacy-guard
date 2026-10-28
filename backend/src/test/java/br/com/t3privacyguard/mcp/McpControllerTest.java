package br.com.t3privacyguard.mcp;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import br.com.t3privacyguard.domain.DecisionType;
import br.com.t3privacyguard.integration.RuntimePolicyClient;
import br.com.t3privacyguard.integration.RuntimePolicyClient.RuntimeDecision;
import br.com.t3privacyguard.integration.RuntimeRemediationClient;
import br.com.t3privacyguard.integration.RuntimeRemediationClient.VerificationResult;
import br.com.t3privacyguard.integration.RuntimeStatusClient;
import br.com.t3privacyguard.integration.RuntimeStatusClient.ContractIdentity;
import br.com.t3privacyguard.integration.TrustRuntimeUnavailableException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

@SpringBootTest
@AutoConfigureMockMvc
class McpControllerTest {
    private static final String TOKEN = "test-mcp-token-123456789012345678901234";

    @Autowired MockMvc mvc;
    @MockitoBean RuntimeStatusClient status;
    @MockitoBean RuntimePolicyClient policy;
    @MockitoBean RuntimeRemediationClient remediation;

    private ResultActions rpc(String body) throws Exception {
        return mvc.perform(post("/mcp").header("Authorization", "Bearer " + TOKEN).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    @Test
    void requiresTheMcpBearerToken() throws Exception {
        mvc.perform(post("/mcp").contentType(MediaType.APPLICATION_JSON).content("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string("WWW-Authenticate", "Bearer realm=\"privacy-guard-mcp\""));
        mvc.perform(post("/mcp").header("Authorization", "Bearer wrong-token-12345678901234567890123456")
                .contentType(MediaType.APPLICATION_JSON).content("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void negotiatesTheProtocolAndListsOnlyNonExecutingTools() throws Exception {
        rpc("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}")
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.result.protocolVersion").value("2025-06-18"))
            .andExpect(jsonPath("$.result.capabilities.tools").exists());
        rpc("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}").andExpect(status().isAccepted());
        rpc("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}")
            .andExpect(jsonPath("$.result.tools.length()").value(3))
            .andExpect(jsonPath("$.result.tools[?(@.name =~ /.*(execute|authorize).*/)]").isEmpty());
        rpc("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"resources/list\"}").andExpect(jsonPath("$.error.code").value(-32601));
        mvc.perform(get("/mcp").header("Authorization", "Bearer " + TOKEN)).andExpect(status().isMethodNotAllowed());
    }

    @Test
    void evaluatesThroughGuardRuntimeAndFailsClosed() throws Exception {
        when(policy.evaluate(any())).thenReturn(new RuntimeDecision("req-1", DecisionType.DENY, "SECRET_DISCLOSURE_FORBIDDEN", "r",
            List.of(), List.of(), List.of(), List.of(), "v1", "b".repeat(64), true));
        rpc("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"privacy.evaluate_action\",\"arguments\":{\"request_id\":\"req-1\",\"action\":\"revoke-credential\",\"resource\":\"credential:1\",\"purpose\":\"incident-remediation\",\"fields\":[\"api_key\"]}}}")
            .andExpect(jsonPath("$.result.isError").doesNotExist())
            .andExpect(jsonPath("$.result.content[0].text").value(org.hamcrest.Matchers.containsString("\"reason_code\":\"SECRET_DISCLOSURE_FORBIDDEN\"")));

        when(policy.evaluate(any())).thenThrow(new TrustRuntimeUnavailableException("down"));
        rpc("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"privacy.evaluate_action\",\"arguments\":{\"request_id\":\"req-1\",\"action\":\"a\",\"resource\":\"r\",\"purpose\":\"p\",\"fields\":[]}}}")
            .andExpect(jsonPath("$.result.isError").value(true))
            .andExpect(jsonPath("$.result.content[0].text").value("Privacy Guard MCP operation failed closed"));
    }

    @Test
    void rejectsExtraOrInvalidArgumentsBeforeCallingTheRuntime() throws Exception {
        rpc("{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"privacy.evaluate_action\",\"arguments\":{\"request_id\":\"r\",\"action\":\"a\",\"resource\":\"r\",\"purpose\":\"p\",\"fields\":[],\"agent_did\":\"agent:attacker\"}}}")
            .andExpect(jsonPath("$.error.code").value(-32602));
        rpc("{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"privacy.verify_remediation\",\"arguments\":{\"request_id\":\"r\",\"operation_id\":\"op\",\"action\":\"notify-security\",\"expected_state\":\"REVOKED\"}}}")
            .andExpect(jsonPath("$.error.code").value(-32602));
        rpc("{\"jsonrpc\":\"2.0\",\"id\":8,\"method\":\"tools/call\",\"params\":{\"name\":\"privacy.execute_remediation\",\"arguments\":{}}}")
            .andExpect(jsonPath("$.error.code").value(-32602));
        verify(policy, never()).evaluate(any());
        verify(remediation, never()).verify(any(), any());
    }

    @Test
    void identityAndVerificationAreAvailable() throws Exception {
        when(status.contractIdentity()).thenReturn(Optional.of(new ContractIdentity("guard-runtime", "1.0.0")));
        when(remediation.verify("req-1", "op-1")).thenReturn(new VerificationResult("req-1", "VERIFIED", "REVOKED"));
        rpc("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"params\":{\"name\":\"privacy.contract_identity\",\"arguments\":{}}}")
            .andExpect(jsonPath("$.result.content[0].text").value("{\"contractId\":\"guard-runtime\",\"contractVersion\":\"1.0.0\"}"));
        rpc("{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"tools/call\",\"params\":{\"name\":\"privacy.verify_remediation\",\"arguments\":{\"request_id\":\"req-1\",\"operation_id\":\"op-1\",\"action\":\"revoke-credential\",\"expected_state\":\"REVOKED\"}}}")
            .andExpect(jsonPath("$.result.content[0].text").value(org.hamcrest.Matchers.containsString("\"status\":\"VERIFIED\"")));
    }
}
