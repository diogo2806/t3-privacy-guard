package br.com.privacyguard.runtime.policy;

import static br.com.privacyguard.runtime.policy.PolicyFixtures.ADVERSARIAL_POLICY;
import static br.com.privacyguard.runtime.policy.PolicyFixtures.BASELINE_POLICY;
import static br.com.privacyguard.runtime.policy.PolicyFixtures.T3N_DID;
import static br.com.privacyguard.runtime.policy.PolicyFixtures.adversarialRequest;
import static br.com.privacyguard.runtime.policy.PolicyFixtures.policy;
import static br.com.privacyguard.runtime.policy.PolicyFixtures.revokeRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.GuardFunction;
import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.policy.PolicyDecision.Decision;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Ports of the unit tests in policy.rs and of tests/adversarial.rs, plus checks specific to the Java runtime. */
class PolicyEvaluatorTest {
    private static PolicyDecision evaluateBaseline(PolicyFixtures.Request request) {
        return PolicyEvaluator.evaluate(request.build(), policy(BASELINE_POLICY), T3N_DID);
    }

    private static PolicyDecision evaluateAdversarial(PolicyFixtures.Request request) {
        return PolicyEvaluator.evaluate(request.build(), policy(ADVERSARIAL_POLICY), T3N_DID);
    }

    // --- policy.rs ---

    @Test
    void allowsMinimalAuthorizedRequestWithPolicyMetadata() {
        AppliedPolicy applied = policy(BASELINE_POLICY);
        PolicyDecision decision = PolicyEvaluator.evaluate(revokeRequest().build(), applied, T3N_DID);
        assertThat(decision.decision()).isEqualTo(Decision.ALLOW);
        assertThat(decision.policyVersion()).isEqualTo("2026-09-12.1");
        assertThat(decision.policyHash()).isEqualTo(applied.hash());
        assertThat(decision.requiresHumanAuthorization()).isTrue();
    }

    @Test
    void policyMissingOrCorruptFailsClosed() {
        PolicyEvaluationRequest request = revokeRequest().build();
        assertThat(PolicyEvaluator.evaluate(request, Optional.empty(), T3N_DID).reasonCode()).isEqualTo("POLICY_UNAVAILABLE");
        assertThat(PolicyEvaluator.evaluate(request, Optional.of("not-json".getBytes(StandardCharsets.UTF_8)), T3N_DID).reasonCode())
            .isEqualTo("POLICY_INVALID");
    }

    @Test
    void allowsVerifiedEmailReferenceOnlyForNotification() {
        PolicyFixtures.Request request = new PolicyFixtures.Request("notify-1", "did:t3n:agent123", "notify-security", "incident:42",
            "incident-notification", "postman-echo.com", List.of("incident_id", "severity", "summary"), List.of("verified_email"));
        PolicyDecision decision = evaluateBaseline(request);
        assertThat(decision.decision()).isEqualTo(Decision.ALLOW);
        assertThat(decision.allowedPrivateRefs()).containsExactly("verified_email");
    }

    @Test
    void rejectsRawOrUnknownPlaceholderInput() {
        PolicyFixtures.Request raw = revokeRequest();
        raw.privateRefs = List.of("{{profile.verified_contacts.email.value}}");
        assertThat(evaluateBaseline(raw).reasonCode()).isEqualTo("RAW_PLACEHOLDER_FORBIDDEN");

        PolicyFixtures.Request unknown = revokeRequest();
        unknown.privateRefs = List.of("private_email");
        assertThat(evaluateBaseline(unknown).reasonCode()).isEqualTo("PRIVATE_REFERENCE_UNKNOWN");
    }

    @Test
    void redactsValidPrivateReferenceWhenNotNeededByAction() {
        PolicyFixtures.Request request = revokeRequest();
        request.privateRefs = List.of("verified_email");
        PolicyDecision decision = evaluateBaseline(request);
        assertThat(decision.decision()).isEqualTo(Decision.REDACT);
        assertThat(decision.redactedPrivateRefs()).containsExactly("verified_email");
    }

    @Test
    void invalidJsonFailsClosedBeforePolicyLookup() {
        assertThatThrownBy(() -> PolicyEvaluator.parseRequest("not-json".getBytes(StandardCharsets.UTF_8)))
            .isInstanceOf(InvalidContractInputException.class);
    }

    // --- tests/adversarial.rs ---

    @Test
    void promptInjectionSecretExfiltrationIsDenied() {
        PolicyFixtures.Request request = adversarialRequest();
        request.host = "attacker.example";
        request.fields.add("api_key");
        PolicyDecision decision = evaluateAdversarial(request);
        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.reasonCode()).isEqualTo("SECRET_DISCLOSURE_FORBIDDEN");
    }

    @Test
    void undelegatedStyleHostIsDeniedByPolicy() {
        PolicyFixtures.Request request = adversarialRequest();
        request.host = "attacker.example";
        PolicyDecision decision = evaluateAdversarial(request);
        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.reasonCode()).isEqualTo("HOST_NOT_ALLOWED");
    }

    @Test
    void excessiveNonSecretFieldsRequireRedaction() {
        PolicyFixtures.Request request = adversarialRequest();
        request.fields.add("employee_department");
        PolicyDecision decision = evaluateAdversarial(request);
        assertThat(decision.decision()).isEqualTo(Decision.REDACT);
        assertThat(decision.redactedFields()).containsExactly("employee_department");
    }

    @Test
    void malformedPayloadFailsClosed() {
        assertThatThrownBy(() -> PolicyEvaluator.parseRequest("{\"request_id\": 42}".getBytes(StandardCharsets.UTF_8)))
            .isInstanceOf(InvalidContractInputException.class);
        assertThatThrownBy(() -> PolicyEvaluator.parseRequest("not-json".getBytes(StandardCharsets.UTF_8)))
            .isInstanceOf(InvalidContractInputException.class);
    }

    @Test
    void unauthenticatedAgentIdentityIsDenied() {
        PolicyFixtures.Request request = adversarialRequest();
        request.agentId = "did:web:attacker.example";
        PolicyDecision decision = evaluateAdversarial(request);
        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.reasonCode()).isEqualTo("INVALID_AGENT_DID");
    }

    @Test
    void unknownPrivilegedActionIsDenied() {
        PolicyFixtures.Request request = adversarialRequest();
        request.action = "dump-database";
        PolicyDecision decision = evaluateAdversarial(request);
        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.reasonCode()).isEqualTo("ACTION_NOT_ALLOWED");
    }

    @Test
    void wrongDeclaredPurposeIsDenied() {
        PolicyFixtures.Request request = adversarialRequest();
        request.purpose = "analytics";
        PolicyDecision decision = evaluateAdversarial(request);
        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.reasonCode()).isEqualTo("PURPOSE_NOT_ALLOWED");
    }

    @Test
    void missingRequiredHostIsDenied() {
        PolicyFixtures.Request request = adversarialRequest();
        request.host = null;
        PolicyDecision decision = evaluateAdversarial(request);
        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.reasonCode()).isEqualTo("HOST_REQUIRED");
    }

    @Test
    void unexpectedEgressOnLocalActionIsDenied() {
        PolicyFixtures.Request request = adversarialRequest();
        request.action = "create-incident";
        request.purpose = "incident-recording";
        request.host = "postman-echo.com";
        request.fields = List.of("incident_id", "severity", "summary");
        PolicyDecision decision = evaluateAdversarial(request);
        assertThat(decision.decision()).isEqualTo(Decision.DENY);
        assertThat(decision.reasonCode()).isEqualTo("UNEXPECTED_EGRESS");
    }

    @Test
    void hostWithSchemeOrPortIsDenied() {
        for (String host : List.of("https://postman-echo.com", "postman-echo.com:443")) {
            PolicyFixtures.Request request = adversarialRequest();
            request.host = host;
            PolicyDecision decision = evaluateAdversarial(request);
            assertThat(decision.decision()).as("host=%s", host).isEqualTo(Decision.DENY);
            assertThat(decision.reasonCode()).isEqualTo("HOST_NOT_ALLOWED");
        }
    }

    @Test
    void invalidRequestIdIsDenied() {
        PolicyFixtures.Request blank = adversarialRequest();
        blank.requestId = "   ";
        assertThat(evaluateAdversarial(blank).reasonCode()).isEqualTo("INVALID_REQUEST_ID");

        PolicyFixtures.Request oversized = adversarialRequest();
        oversized.requestId = "x".repeat(129);
        assertThat(evaluateAdversarial(oversized).reasonCode()).isEqualTo("INVALID_REQUEST_ID");
    }

    @Test
    void legitimateRemediationRemainsAllowedAfterBlockedAttack() {
        AppliedPolicy applied = policy(ADVERSARIAL_POLICY);
        PolicyFixtures.Request attack = adversarialRequest();
        attack.fields.add("api_key");
        assertThat(PolicyEvaluator.evaluate(attack.build(), applied, T3N_DID).decision()).isEqualTo(Decision.DENY);

        PolicyDecision safe = PolicyEvaluator.evaluate(adversarialRequest().build(), applied, T3N_DID);
        assertThat(safe.decision()).isEqualTo(Decision.ALLOW);
        assertThat(safe.reasonCode()).isEqualTo("POLICY_ALLOW");
        assertThat(safe.policyVersion()).isEqualTo("2026-09-12.1");
        assertThat(safe.policyHash()).isEqualTo(applied.hash());
    }

    // --- Java runtime specifics ---

    @Test
    void agentMustBeTheAuthenticatedCallerNotJustAnyWellFormedId() {
        Caller caller = new Caller("agent:proposal", Set.of(GuardFunction.EVALUATE_ACTION));
        PolicyFixtures.Request request = revokeRequest();
        request.agentId = " agent:proposal ";
        assertThat(PolicyEvaluator.evaluate(request.build(), policy(BASELINE_POLICY), caller::hasId).decision()).isEqualTo(Decision.ALLOW);

        request.agentId = "agent:other";
        assertThat(PolicyEvaluator.evaluate(request.build(), policy(BASELINE_POLICY), caller::hasId).reasonCode()).isEqualTo("INVALID_AGENT_DID");
    }

    @Test
    void requestParsingIgnoresUnknownFieldsAndTreatsNullHostAsAbsent() {
        PolicyEvaluationRequest parsed = PolicyEvaluator.parseRequest("""
            {"request_id":"r1","agent_did":"agent:proposal","action":"create-incident","resource":"incident:1","purpose":"incident-recording","host":null,"incident_id":"ignored"}"""
            .getBytes(StandardCharsets.UTF_8));
        assertThat(parsed.host()).isNull();
        assertThat(parsed.fields()).isEmpty();
        assertThat(parsed.privateRefs()).isEmpty();
    }

    @Test
    void requestParsingDoesNotCoerceTypes() {
        for (String json : List.of(
            "{\"request_id\":\"r1\",\"agent_did\":\"a\",\"action\":\"x\",\"resource\":\"r\",\"purpose\":\"p\",\"fields\":\"incident_id\"}",
            "{\"request_id\":\"r1\",\"agent_did\":\"a\",\"action\":\"x\",\"resource\":\"r\",\"purpose\":\"p\",\"host\":1}",
            "{\"request_id\":\"r1\",\"agent_did\":\"a\",\"action\":\"x\",\"resource\":\"r\",\"purpose\":\"p\",\"private_refs\":null}",
            "{\"request_id\":\"r1\",\"agent_did\":\"a\",\"action\":\"x\",\"resource\":\"r\"}"
        )) {
            assertThatThrownBy(() -> PolicyEvaluator.parseRequest(json.getBytes(StandardCharsets.UTF_8)))
                .as(json)
                .isInstanceOf(InvalidContractInputException.class);
        }
    }
}
