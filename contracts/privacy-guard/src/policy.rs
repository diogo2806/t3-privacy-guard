use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyEvaluationRequest {
    pub request_id: String,
    pub agent_did: String,
    pub action: String,
    pub resource: String,
    pub purpose: String,
    pub host: Option<String>,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub private_refs: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Redact,
    Deny,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub request_id: String,
    pub decision: Decision,
    pub reason_code: String,
    pub reason: String,
    pub allowed_fields: Vec<String>,
    pub redacted_fields: Vec<String>,
    pub allowed_private_refs: Vec<String>,
    pub redacted_private_refs: Vec<String>,
}

#[derive(Debug, Clone)]
struct ActionPolicy {
    purpose: &'static str,
    allowed_fields: &'static [&'static str],
    allowed_hosts: &'static [&'static str],
    allowed_private_refs: &'static [&'static str],
    requires_host: bool,
}

const FORBIDDEN_SECRET_FIELDS: &[&str] = &[
    "api_key", "card_number", "credential", "cpf", "password", "private_key", "secret", "ssn", "token",
];
const KNOWN_PRIVATE_REFS: &[&str] = &["verified_email"];

fn normalized(value: &str) -> String { value.trim().to_ascii_lowercase() }

fn action_policy(action: &str) -> Option<ActionPolicy> {
    match action {
        "revoke-credential" => Some(ActionPolicy {
            purpose: "incident-remediation",
            allowed_fields: &["incident_id", "credential_id", "reason"],
            allowed_hosts: &["security-api.internal", "postman-echo.com"],
            allowed_private_refs: &[],
            requires_host: true,
        }),
        "isolate-account" => Some(ActionPolicy {
            purpose: "incident-remediation",
            allowed_fields: &["incident_id", "account_id", "reason"],
            allowed_hosts: &["security-api.internal", "postman-echo.com"],
            allowed_private_refs: &[],
            requires_host: true,
        }),
        "create-incident" => Some(ActionPolicy {
            purpose: "incident-recording",
            allowed_fields: &["incident_id", "severity", "summary", "source"],
            allowed_hosts: &[],
            allowed_private_refs: &[],
            requires_host: false,
        }),
        "notify-security" => Some(ActionPolicy {
            purpose: "incident-notification",
            allowed_fields: &["incident_id", "severity", "summary"],
            allowed_hosts: &["security-api.internal", "postman-echo.com"],
            allowed_private_refs: &["verified_email"],
            requires_host: true,
        }),
        _ => None,
    }
}

fn deny(request_id: &str, code: &str, reason: &str) -> PolicyDecision {
    PolicyDecision {
        request_id: request_id.to_string(), decision: Decision::Deny, reason_code: code.to_string(), reason: reason.to_string(),
        allowed_fields: vec![], redacted_fields: vec![], allowed_private_refs: vec![], redacted_private_refs: vec![],
    }
}

pub fn evaluate(request: &PolicyEvaluationRequest) -> PolicyDecision {
    let request_id = request.request_id.trim();
    if request_id.is_empty() || request_id.len() > 128 {
        return deny(request_id, "INVALID_REQUEST_ID", "Request id is required and must be at most 128 characters");
    }
    if !request.agent_did.trim().starts_with("did:t3n:") {
        return deny(request_id, "INVALID_AGENT_DID", "Agent identity must be an authenticated T3N DID");
    }
    if request.resource.trim().is_empty() { return deny(request_id, "INVALID_RESOURCE", "Resource is required"); }

    let action = normalized(&request.action);
    let Some(policy) = action_policy(&action) else {
        return deny(request_id, "ACTION_NOT_ALLOWED", "Requested action is not allowed by policy");
    };
    if normalized(&request.purpose) != policy.purpose {
        return deny(request_id, "PURPOSE_NOT_ALLOWED", "Declared purpose does not authorize this action");
    }

    let requested_fields: BTreeSet<String> = request.fields.iter().map(|field| normalized(field)).filter(|field| !field.is_empty()).collect();
    if requested_fields.iter().any(|field| FORBIDDEN_SECRET_FIELDS.contains(&field.as_str())) {
        return deny(request_id, "SECRET_DISCLOSURE_FORBIDDEN", "Direct disclosure of secrets or high-risk credentials is forbidden");
    }

    let requested_private_refs: BTreeSet<String> = request.private_refs.iter().map(|value| normalized(value)).filter(|value| !value.is_empty()).collect();
    if requested_private_refs.iter().any(|value| value.contains("{{") || value.contains("}}") || value.starts_with("profile.")) {
        return deny(request_id, "RAW_PLACEHOLDER_FORBIDDEN", "Clients must use logical private-data references, not T3N placeholder strings");
    }
    if requested_private_refs.iter().any(|value| !KNOWN_PRIVATE_REFS.contains(&value.as_str())) {
        return deny(request_id, "PRIVATE_REFERENCE_UNKNOWN", "Requested private-data reference is not recognized by the contract");
    }

    let host = request.host.as_deref().map(normalized).filter(|value| !value.is_empty());
    if policy.requires_host {
        let Some(host) = host.as_deref() else { return deny(request_id, "HOST_REQUIRED", "This action requires an explicitly authorized destination host"); };
        if host.contains('/') || host.contains(':') || !policy.allowed_hosts.contains(&host) {
            return deny(request_id, "HOST_NOT_ALLOWED", "Destination host is outside the policy allowlist");
        }
    } else if host.is_some() {
        return deny(request_id, "UNEXPECTED_EGRESS", "This action does not require outbound network access");
    }

    let allowed_fields_set: BTreeSet<&str> = policy.allowed_fields.iter().copied().collect();
    let mut allowed_fields = Vec::new();
    let mut redacted_fields = Vec::new();
    for field in requested_fields {
        if allowed_fields_set.contains(field.as_str()) { allowed_fields.push(field); } else { redacted_fields.push(field); }
    }

    let allowed_private_set: BTreeSet<&str> = policy.allowed_private_refs.iter().copied().collect();
    let mut allowed_private_refs = Vec::new();
    let mut redacted_private_refs = Vec::new();
    for private_ref in requested_private_refs {
        if allowed_private_set.contains(private_ref.as_str()) { allowed_private_refs.push(private_ref); } else { redacted_private_refs.push(private_ref); }
    }

    let requires_minimization = !redacted_fields.is_empty() || !redacted_private_refs.is_empty();
    PolicyDecision {
        request_id: request_id.to_string(),
        decision: if requires_minimization { Decision::Redact } else { Decision::Allow },
        reason_code: if requires_minimization { "DATA_MINIMIZATION_REQUIRED" } else { "POLICY_ALLOW" }.to_string(),
        reason: if requires_minimization {
            "Action is allowed only after removing data or private references unnecessary for the declared purpose"
        } else {
            "Action and requested data satisfy the minimum policy scope"
        }.to_string(),
        allowed_fields,
        redacted_fields,
        allowed_private_refs,
        redacted_private_refs,
    }
}

pub fn evaluate_json(input: &[u8]) -> Result<Vec<u8>, String> {
    let request: PolicyEvaluationRequest = serde_json::from_slice(input).map_err(|_| "evaluate-action: invalid JSON input".to_string())?;
    serde_json::to_vec(&evaluate(&request)).map_err(|_| "evaluate-action: failed to encode decision".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> PolicyEvaluationRequest {
        PolicyEvaluationRequest {
            request_id: "req-001".into(), agent_did: "did:t3n:agent123".into(), action: "revoke-credential".into(),
            resource: "credential:cred-42".into(), purpose: "incident-remediation".into(), host: Some("postman-echo.com".into()),
            fields: vec!["incident_id".into(), "credential_id".into(), "reason".into()], private_refs: vec![],
        }
    }

    #[test] fn allows_minimal_authorized_request() { assert_eq!(evaluate(&request()).decision, Decision::Allow); }

    #[test]
    fn allows_verified_email_reference_only_for_notification() {
        let value = PolicyEvaluationRequest {
            request_id: "notify-1".into(), agent_did: "did:t3n:agent123".into(), action: "notify-security".into(),
            resource: "incident:42".into(), purpose: "incident-notification".into(), host: Some("postman-echo.com".into()),
            fields: vec!["incident_id".into(), "severity".into(), "summary".into()], private_refs: vec!["verified_email".into()],
        };
        let decision = evaluate(&value);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.allowed_private_refs, vec!["verified_email"]);
    }

    #[test]
    fn rejects_raw_or_unknown_placeholder_input() {
        let mut raw = request(); raw.private_refs = vec!["{{profile.verified_contacts.email.value}}".into()];
        assert_eq!(evaluate(&raw).reason_code, "RAW_PLACEHOLDER_FORBIDDEN");
        let mut unknown = request(); unknown.private_refs = vec!["private_email".into()];
        assert_eq!(evaluate(&unknown).reason_code, "PRIVATE_REFERENCE_UNKNOWN");
    }

    #[test]
    fn redacts_valid_private_reference_when_not_needed_by_action() {
        let mut value = request(); value.private_refs = vec!["verified_email".into()];
        let decision = evaluate(&value);
        assert_eq!(decision.decision, Decision::Redact);
        assert_eq!(decision.redacted_private_refs, vec!["verified_email"]);
    }

    #[test]
    fn redacts_unnecessary_non_secret_fields() {
        let mut value = request(); value.fields.push("employee_department".into());
        let decision = evaluate(&value);
        assert_eq!(decision.decision, Decision::Redact);
        assert_eq!(decision.redacted_fields, vec!["employee_department"]);
    }

    #[test]
    fn denies_secret_disclosure() {
        let mut value = request(); value.fields.push("api_key".into());
        let decision = evaluate(&value);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, "SECRET_DISCLOSURE_FORBIDDEN");
    }

    #[test]
    fn denies_unapproved_host() {
        let mut value = request(); value.host = Some("attacker.example".into());
        let decision = evaluate(&value);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, "HOST_NOT_ALLOWED");
    }

    #[test]
    fn denies_unknown_action_and_wrong_purpose() {
        let mut unknown = request(); unknown.action = "dump-database".into();
        assert_eq!(evaluate(&unknown).reason_code, "ACTION_NOT_ALLOWED");
        let mut wrong_purpose = request(); wrong_purpose.purpose = "analytics".into();
        assert_eq!(evaluate(&wrong_purpose).reason_code, "PURPOSE_NOT_ALLOWED");
    }

    #[test] fn result_is_deterministic() { let value = request(); assert_eq!(evaluate(&value), evaluate(&value)); }
    #[test] fn invalid_json_fails_closed() { assert!(evaluate_json(b"not-json").is_err()); }
}
