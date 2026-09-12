use privacy_guard_contract::policy::{evaluate, evaluate_json, Decision, PolicyEvaluationRequest};
use proptest::prelude::*;
use std::collections::BTreeSet;

const FORBIDDEN: &[&str] = &[
    "api_key", "card_number", "credential", "cpf", "password", "private_key", "secret", "ssn", "token",
];

fn allowed_request(action: usize) -> PolicyEvaluationRequest {
    match action % 4 {
        0 => PolicyEvaluationRequest {
            request_id: "property-revoke".into(),
            agent_did: "did:t3n:property-agent".into(),
            action: "revoke-credential".into(),
            resource: "credential:test".into(),
            purpose: "incident-remediation".into(),
            host: Some("postman-echo.com".into()),
            fields: vec!["incident_id".into(), "credential_id".into(), "reason".into()],
            private_refs: vec![],
        },
        1 => PolicyEvaluationRequest {
            request_id: "property-isolate".into(),
            agent_did: "did:t3n:property-agent".into(),
            action: "isolate-account".into(),
            resource: "account:test".into(),
            purpose: "incident-remediation".into(),
            host: Some("security-api.internal".into()),
            fields: vec!["incident_id".into(), "account_id".into(), "reason".into()],
            private_refs: vec![],
        },
        2 => PolicyEvaluationRequest {
            request_id: "property-create".into(),
            agent_did: "did:t3n:property-agent".into(),
            action: "create-incident".into(),
            resource: "incident:test".into(),
            purpose: "incident-recording".into(),
            host: None,
            fields: vec!["incident_id".into(), "severity".into(), "summary".into(), "source".into()],
            private_refs: vec![],
        },
        _ => PolicyEvaluationRequest {
            request_id: "property-notify".into(),
            agent_did: "did:t3n:property-agent".into(),
            action: "notify-security".into(),
            resource: "incident:test".into(),
            purpose: "incident-notification".into(),
            host: Some("postman-echo.com".into()),
            fields: vec!["incident_id".into(), "severity".into(), "summary".into()],
            private_refs: vec!["verified_email".into()],
        },
    }
}

fn expected_fields(action: &str) -> BTreeSet<&'static str> {
    match action {
        "revoke-credential" => ["incident_id", "credential_id", "reason"].into_iter().collect(),
        "isolate-account" => ["incident_id", "account_id", "reason"].into_iter().collect(),
        "create-incident" => ["incident_id", "severity", "summary", "source"].into_iter().collect(),
        "notify-security" => ["incident_id", "severity", "summary"].into_iter().collect(),
        _ => BTreeSet::new(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, .. ProptestConfig::default() })]

    #[test]
    fn forbidden_secret_is_never_allowed(
        action in 0usize..4,
        secret_index in 0usize..FORBIDDEN.len(),
        duplicate_count in 1usize..6,
    ) {
        let mut request = allowed_request(action);
        let secret = FORBIDDEN[secret_index];
        for _ in 0..duplicate_count { request.fields.push(secret.to_string()); }
        let decision = evaluate(&request);
        prop_assert_eq!(decision.decision, Decision::Deny);
        prop_assert_eq!(decision.reason_code, "SECRET_DISCLOSURE_FORBIDDEN");
        prop_assert!(!decision.allowed_fields.iter().any(|field| field == secret));
    }

    #[test]
    fn allow_implies_complete_action_policy(
        action in 0usize..4,
        duplicate_fields in 0usize..5,
    ) {
        let mut request = allowed_request(action);
        if duplicate_fields > 0 {
            let first = request.fields[0].clone();
            for _ in 0..duplicate_fields { request.fields.push(first.clone()); }
        }
        let decision = evaluate(&request);
        prop_assert_eq!(decision.decision, Decision::Allow);

        let expected = expected_fields(&request.action);
        prop_assert!(decision.allowed_fields.iter().all(|field| expected.contains(field.as_str())));
        prop_assert!(decision.allowed_fields.iter().all(|field| !FORBIDDEN.contains(&field.as_str())));
        prop_assert!(decision.redacted_fields.is_empty());
        prop_assert!(decision.redacted_private_refs.is_empty());
        if request.action == "notify-security" {
            prop_assert_eq!(decision.allowed_private_refs, vec!["verified_email"]);
        } else {
            prop_assert!(decision.allowed_private_refs.is_empty());
        }
    }

    #[test]
    fn privilege_increase_never_improves_an_allowed_decision(
        action in 0usize..4,
        mutation in 0usize..4,
        suffix in "[a-z0-9_]{1,24}",
    ) {
        let mut request = allowed_request(action);
        prop_assert_eq!(evaluate(&request).decision, Decision::Allow);

        match mutation {
            0 => request.fields.push(format!("extra_{suffix}")),
            1 => request.fields.push("api_key".into()),
            2 => request.private_refs.push("unknown_private_ref".into()),
            _ => request.purpose = "unrelated-purpose".into(),
        }
        prop_assert_ne!(evaluate(&request).decision, Decision::Allow);
    }

    #[test]
    fn normalization_cannot_hide_forbidden_secret(
        action in 0usize..4,
        secret_index in 0usize..FORBIDDEN.len(),
        leading in 0usize..5,
        trailing in 0usize..5,
        uppercase in any::<bool>(),
    ) {
        let mut request = allowed_request(action);
        let base = FORBIDDEN[secret_index];
        let value = if uppercase { base.to_ascii_uppercase() } else { base.to_string() };
        request.fields.push(format!("{}{}{}", " ".repeat(leading), value, " ".repeat(trailing)));
        let decision = evaluate(&request);
        prop_assert_eq!(decision.decision, Decision::Deny);
        prop_assert_eq!(decision.reason_code, "SECRET_DISCLOSURE_FORBIDDEN");
    }

    #[test]
    fn arbitrary_input_never_panics(input in prop::collection::vec(any::<u8>(), 0..4096)) {
        let result = std::panic::catch_unwind(|| evaluate_json(&input));
        prop_assert!(result.is_ok());
    }

    #[test]
    fn raw_or_unknown_private_reference_never_becomes_allowed(
        action in 0usize..4,
        generated in "[a-z][a-z0-9_]{1,40}",
    ) {
        let mut request = allowed_request(action);
        let private_ref = if generated == "verified_email" { "not_verified_email".to_string() } else { generated };
        request.private_refs.push(private_ref.clone());
        let decision = evaluate(&request);
        prop_assert_ne!(decision.decision, Decision::Allow);
        prop_assert!(!decision.allowed_private_refs.contains(&private_ref));
    }
}
