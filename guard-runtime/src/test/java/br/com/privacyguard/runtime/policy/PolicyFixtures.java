package br.com.privacyguard.runtime.policy;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/** Policies and requests copied from the Rust contract tests (policy.rs, adversarial.rs, properties.rs). */
final class PolicyFixtures {
    /** What the Rust contract accepted as an authenticated agent; used where tests must match the original exactly. */
    static final Predicate<String> T3N_DID = agentId -> agentId.startsWith("did:t3n:");

    static final String BASELINE_POLICY = """
        {
          "version":"2026-09-12.1",
          "actions":{
            "create-incident":{"purpose":"incident-recording","allowed_fields":["incident_id","severity","summary","source"],"allowed_hosts":[],"allowed_private_refs":[],"requires_host":false,"requires_human_authorization":false},
            "isolate-account":{"purpose":"incident-remediation","allowed_fields":["incident_id","account_id","reason"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true},
            "notify-security":{"purpose":"incident-notification","allowed_fields":["incident_id","severity","summary"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":["verified_email"],"requires_host":true,"requires_human_authorization":false},
            "revoke-credential":{"purpose":"incident-remediation","allowed_fields":["incident_id","credential_id","reason"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}
          }
        }""";

    static final String ADVERSARIAL_POLICY = """
        {
          "version":"2026-09-12.1",
          "actions":{
            "create-incident":{"purpose":"incident-recording","allowed_fields":["incident_id","severity","summary","source"],"allowed_hosts":[],"allowed_private_refs":[],"requires_host":false,"requires_human_authorization":false},
            "notify-security":{"purpose":"incident-notification","allowed_fields":["incident_id","severity","summary"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":["verified_email"],"requires_host":true,"requires_human_authorization":false},
            "revoke-credential":{"purpose":"incident-remediation","allowed_fields":["incident_id","credential_id","reason"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}
          }
        }""";

    /** Same rules as BASELINE_POLICY with the version used by properties.rs. */
    static final String PROPERTY_POLICY = BASELINE_POLICY.replace("2026-09-12.1", "property-v1");

    static final List<String> FORBIDDEN = List.of(
        "api_key", "card_number", "credential", "cpf", "password", "private_key", "secret", "ssn", "token"
    );

    private PolicyFixtures() {}

    static AppliedPolicy policy(String json) {
        return PolicyDocumentParser.parse(json.getBytes(StandardCharsets.UTF_8));
    }

    static Request revokeRequest() {
        return new Request("req-001", "did:t3n:agent123", "revoke-credential", "credential:cred-42", "incident-remediation",
            "postman-echo.com", List.of("incident_id", "credential_id", "reason"), List.of());
    }

    static Request adversarialRequest() {
        return new Request("adv-001", "did:t3n:agent-test", "revoke-credential", "credential:security-api", "incident-remediation",
            "postman-echo.com", List.of("incident_id", "credential_id", "reason"), List.of());
    }

    /** properties.rs allowed_request(action % 4). */
    static Request allowedRequest(int action) {
        return switch (action % 4) {
            case 0 -> new Request("property-revoke", "did:t3n:property-agent", "revoke-credential", "credential:test", "incident-remediation",
                "postman-echo.com", List.of("incident_id", "credential_id", "reason"), List.of());
            case 1 -> new Request("property-isolate", "did:t3n:property-agent", "isolate-account", "account:test", "incident-remediation",
                "security-api.internal", List.of("incident_id", "account_id", "reason"), List.of());
            case 2 -> new Request("property-create", "did:t3n:property-agent", "create-incident", "incident:test", "incident-recording",
                null, List.of("incident_id", "severity", "summary", "source"), List.of());
            default -> new Request("property-notify", "did:t3n:property-agent", "notify-security", "incident:test", "incident-notification",
                "postman-echo.com", List.of("incident_id", "severity", "summary"), List.of("verified_email"));
        };
    }

    /** Mutable builder mirroring the Rust tests' `let mut request = ...; request.x = ...;` style. */
    static final class Request {
        String requestId;
        String agentId;
        String action;
        String resource;
        String purpose;
        String host;
        List<String> fields;
        List<String> privateRefs;

        Request(String requestId, String agentId, String action, String resource, String purpose, String host, List<String> fields, List<String> privateRefs) {
            this.requestId = requestId;
            this.agentId = agentId;
            this.action = action;
            this.resource = resource;
            this.purpose = purpose;
            this.host = host;
            this.fields = new ArrayList<>(fields);
            this.privateRefs = new ArrayList<>(privateRefs);
        }

        PolicyEvaluationRequest build() {
            return new PolicyEvaluationRequest(requestId, agentId, action, resource, purpose, host, fields, privateRefs);
        }
    }
}
