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
}

#[derive(Debug, Clone)]
struct ActionPolicy {
    purpose: &'static str,
    allowed_fields: &'static [&'static str],
    allowed_hosts: &'static [&'static str],
    requires_host: bool,
}

const FORBIDDEN_SECRET_FIELDS: &[&str] = &[
    "api_key",
    "card_number",
    "credential",
    "cpf",
    "password",
    "private_key",
    "secret",
    "ssn",
    "token",
];

fn normalized(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn action_policy(action: &str) -> Option<ActionPolicy> {
    match action {
        "revoke-credential" => Some(ActionPolicy {
            purpose: "incident-remediation",
            allowed_fields: &["incident_id", "credential_id", "reason"],
            allowed_hosts: &["security-api.internal"],
            requires_host: true,
        }),
        "isolate-account" => Some(ActionPolicy {
            purpose: "incident-remediation",
            allowed_fields: &["incident_id", "account_id", "reason"],
            allowed_hosts: &["security-api.internal"],
            requires_host: true,
        }),
        "create-incident" => Some(ActionPolicy {
            purpose: "incident-recording",
            allowed_fields: &["incident_id", "severity", "summary", "source"],
            allowed_hosts: &[],
            requires_host: false,
        }),
        "notify-security" => Some(ActionPolicy {
            purpose: "incident-notification",
            allowed_fields: &["incident_id", "severity", "summary", "contact_email"],
            allowed_hosts: &["security-api.internal"],
            requires_host: true,
        }),
        _ => None,
    }
}

fn deny(request_id: &str, code: &str, reason: &str) -> PolicyDecision {
    PolicyDecision {
        request_id: request_id.to_string(),
        decision: Decision::Deny,
        reason_code: code.to_string(),
        reason: reason.to_string(),
        allowed_fields: vec![],
        redacted_fields: vec![],
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
    if request.resource.trim().is_empty() {
        return deny(request_id, "INVALID_RESOURCE", "Resource is required");
    }

    let action = normalized(&request.action);
    let Some(policy) = action_policy(&action) else {
        return deny(request_id, "ACTION_NOT_ALLOWED", "Requested action is not allowed by policy");
    };

    let purpose = normalized(&request.purpose);
    if purpose != policy.purpose {
        return deny(request_id, "PURPOSE_NOT_ALLOWED", "Declared purpose does not authorize this action");
    }

    let requested_fields: BTreeSet<String> = request.fields.iter().map(|field| normalized(field)).filter(|field| !field.is_empty()).collect();
    if requested_fields.iter().any(|field| FORBIDDEN_SECRET_FIELDS.contains(&field.as_str())) {
        return deny(request_id, "SECRET_DISCLOSURE_FORBIDDEN", "Direct disclosure of secrets or high-risk credentials is forbidden");
    }

    let host = request.host.as_deref().map(normalized).filter(|value| !value.is_empty());
    if policy.requires_host {
        let Some(host) = host.as_deref() else {
            return deny(request_id, "HOST_REQUIRED", "This action requires an explicitly authorized destination host");
        };
        if host.contains('/') || host.contains(':') || !policy.allowed_hosts.contains(&host) {
            return deny(request_id, "HOST_NOT_ALLOWED", "Destination host is outside the policy allowlist");
        }
    } else if host.is_some() {
        return deny(request_id, "UNEXPECTED_EGRESS", "This action does not require outbound network access");
    }

    let allowed: BTreeSet<&str> = policy.allowed_fields.iter().copied().collect();
    let mut allowed_fields = Vec::new();
    let mut redacted_fields = Vec::new();
    for field in requested_fields {
        if allowed.contains(field.as_str()) {
            allowed_fields.push(field);
        } else {
            redacted_fields.push(field);
        }
    }

    if redacted_fields.is_empty() {
        PolicyDecision {
            request_id: request_id.to_string(),
            decision: Decision::Allow,
            reason_code: "POLICY_ALLOW".to_string(),
            reason: "Action and requested data satisfy the minimum policy scope".to_string(),
            allowed_fields,
            redacted_fields,
        }
    } else {
        PolicyDecision {
            request_id: request_id.to_string(),
            decision: Decision::Redact,
            reason_code: "DATA_MINIMIZATION_REQUIRED".to_string(),
            reason: "Action is allowed only after removing fields that are unnecessary for the declared purpose".to_string(),
            allowed_fields,
            redacted_fields,
        }
    }
}

pub fn evaluate_json(input: &[u8]) -> Result<Vec<u8>, String> {
    let request: PolicyEvaluationRequest = serde_json::from_slice(input)
        .map_err(|_| "evaluate-action: invalid JSON input".to_string())?;
    let decision = evaluate(&request);
    serde_json::to_vec(&decision).map_err(|_| "evaluate-action: failed to encode decision".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> PolicyEvaluationRequest {
        PolicyEvaluationRequest {
            request_id: "req-001".into(),
            agent_did: "did:t3n:agent123".into(),
            action: "revoke-credential".into(),
            resource: "credential:cred-42".into(),
            purpose: "incident-remediation".into(),
            host: Some("security-api.internal".into()),
            fields: vec!["incident_id".into(), "credential_id".into(), "reason".into()],
        }
    }

    #[test]
    fn allows_minimal_authorized_request() {
        assert_eq!(evaluate(&request()).decision, Decision::Allow);
    }

    #[test]
    fn redacts_unnecessary_non_secret_fields() {
        let mut value = request();
        value.fields.push("employee_department".into());
        let decision = evaluate(&value);
        assert_eq!(decision.decision, Decision::Redact);
        assert_eq!(decision.redacted_fields, vec!["employee_department"]);
    }

    #[test]
    fn denies_secret_disclosure() {
        let mut value = request();
        value.fields.push("api_key".into());
        let decision = evaluate(&value);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, "SECRET_DISCLOSURE_FORBIDDEN");
    }

    #[test]
    fn denies_unapproved_host() {
        let mut value = request();
        value.host = Some("attacker.example".into());
        let decision = evaluate(&value);
        assert_eq!(decision.decision, Decision::Deny);
        assert_eq!(decision.reason_code, "HOST_NOT_ALLOWED");
    }

    #[test]
    fn denies_unknown_action_and_wrong_purpose() {
        let mut unknown = request();
        unknown.action = "dump-database".into();
        assert_eq!(evaluate(&unknown).reason_code, "ACTION_NOT_ALLOWED");

        let mut wrong_purpose = request();
        wrong_purpose.purpose = "analytics".into();
        assert_eq!(evaluate(&wrong_purpose).reason_code, "PURPOSE_NOT_ALLOWED");
    }

    #[test]
    fn result_is_deterministic() {
        let value = request();
        assert_eq!(evaluate(&value), evaluate(&value));
    }

    #[test]
    fn invalid_json_fails_closed() {
        assert!(evaluate_json(b"not-json").is_err());
    }
}
