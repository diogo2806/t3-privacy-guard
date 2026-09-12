use privacy_guard_contract::policy::{evaluate_json, evaluate_with_policy, parse_policy_document, AppliedPolicy, Decision, PolicyEvaluationRequest};

fn policy() -> AppliedPolicy {
    parse_policy_document(br#"{
      "version":"2026-09-12.1",
      "actions":{
        "create-incident":{"purpose":"incident-recording","allowed_fields":["incident_id","severity","summary","source"],"allowed_hosts":[],"allowed_private_refs":[],"requires_host":false,"requires_human_authorization":false},
        "notify-security":{"purpose":"incident-notification","allowed_fields":["incident_id","severity","summary"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":["verified_email"],"requires_host":true,"requires_human_authorization":false},
        "revoke-credential":{"purpose":"incident-remediation","allowed_fields":["incident_id","credential_id","reason"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}
      }
    }"#).unwrap()
}

fn base_request() -> PolicyEvaluationRequest {
    PolicyEvaluationRequest {
        request_id: "adv-001".into(),
        agent_did: "did:t3n:agent-test".into(),
        action: "revoke-credential".into(),
        resource: "credential:security-api".into(),
        purpose: "incident-remediation".into(),
        host: Some("postman-echo.com".into()),
        fields: vec!["incident_id".into(), "credential_id".into(), "reason".into()],
        private_refs: vec![],
    }
}

#[test]
fn prompt_injection_secret_exfiltration_is_denied() {
    let mut request = base_request();
    request.host = Some("attacker.example".into());
    request.fields.push("api_key".into());
    let decision = evaluate_with_policy(&request, &policy());
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, "SECRET_DISCLOSURE_FORBIDDEN");
}

#[test]
fn undelegated_style_host_is_denied_by_policy() {
    let mut request = base_request();
    request.host = Some("attacker.example".into());
    let decision = evaluate_with_policy(&request, &policy());
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, "HOST_NOT_ALLOWED");
}

#[test]
fn excessive_non_secret_fields_require_redaction() {
    let mut request = base_request();
    request.fields.push("employee_department".into());
    let decision = evaluate_with_policy(&request, &policy());
    assert_eq!(decision.decision, Decision::Redact);
    assert_eq!(decision.redacted_fields, vec!["employee_department"]);
}

#[test]
fn malformed_payload_fails_closed() {
    assert!(evaluate_json(br#"{"request_id": 42}"#).is_err());
    assert!(evaluate_json(b"not-json").is_err());
}

#[test]
fn non_t3n_agent_identity_is_denied() {
    let mut request = base_request();
    request.agent_did = "did:web:attacker.example".into();
    let decision = evaluate_with_policy(&request, &policy());
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, "INVALID_AGENT_DID");
}

#[test]
fn unknown_privileged_action_is_denied() {
    let mut request = base_request();
    request.action = "dump-database".into();
    let decision = evaluate_with_policy(&request, &policy());
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, "ACTION_NOT_ALLOWED");
}

#[test]
fn wrong_declared_purpose_is_denied() {
    let mut request = base_request();
    request.purpose = "analytics".into();
    let decision = evaluate_with_policy(&request, &policy());
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, "PURPOSE_NOT_ALLOWED");
}

#[test]
fn missing_required_host_is_denied() {
    let mut request = base_request();
    request.host = None;
    let decision = evaluate_with_policy(&request, &policy());
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, "HOST_REQUIRED");
}

#[test]
fn unexpected_egress_on_local_action_is_denied() {
    let mut request = base_request();
    request.action = "create-incident".into();
    request.purpose = "incident-recording".into();
    request.host = Some("postman-echo.com".into());
    request.fields = vec!["incident_id".into(), "severity".into(), "summary".into()];
    let decision = evaluate_with_policy(&request, &policy());
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason_code, "UNEXPECTED_EGRESS");
}

#[test]
fn host_with_scheme_or_port_is_denied() {
    for host in ["https://postman-echo.com", "postman-echo.com:443"] {
        let mut request = base_request();
        request.host = Some(host.into());
        let decision = evaluate_with_policy(&request, &policy());
        assert_eq!(decision.decision, Decision::Deny, "host={host}");
        assert_eq!(decision.reason_code, "HOST_NOT_ALLOWED");
    }
}

#[test]
fn invalid_request_id_is_denied() {
    let mut blank = base_request();
    blank.request_id = "   ".into();
    assert_eq!(evaluate_with_policy(&blank, &policy()).reason_code, "INVALID_REQUEST_ID");

    let mut oversized = base_request();
    oversized.request_id = "x".repeat(129);
    assert_eq!(evaluate_with_policy(&oversized, &policy()).reason_code, "INVALID_REQUEST_ID");
}

#[test]
fn legitimate_remediation_remains_allowed_after_blocked_attack() {
    let applied = policy();
    let mut attack = base_request();
    attack.fields.push("api_key".into());
    assert_eq!(evaluate_with_policy(&attack, &applied).decision, Decision::Deny);

    let safe = base_request();
    let safe_decision = evaluate_with_policy(&safe, &applied);
    assert_eq!(safe_decision.decision, Decision::Allow);
    assert_eq!(safe_decision.reason_code, "POLICY_ALLOW");
    assert_eq!(safe_decision.policy_version.as_deref(), Some("2026-09-12.1"));
    assert_eq!(safe_decision.policy_hash.as_deref(), Some(applied.hash.as_str()));
}
