use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_POLICY_BYTES: usize = 32 * 1024;
const MAX_ACTIONS: usize = 16;
const MAX_FIELDS: usize = 64;
const MAX_HOSTS: usize = 16;
const MAX_PRIVATE_REFS: usize = 8;
const MAX_VERSION_LEN: usize = 64;
const MAX_NAME_LEN: usize = 80;
const MAX_HOST_LEN: usize = 253;

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
    pub policy_version: Option<String>,
    pub policy_hash: Option<String>,
    pub requires_human_authorization: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub version: String,
    pub actions: BTreeMap<String, ActionPolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ActionPolicy {
    pub purpose: String,
    #[serde(default)]
    pub allowed_fields: Vec<String>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_private_refs: Vec<String>,
    pub requires_host: bool,
    #[serde(default)]
    pub requires_human_authorization: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedPolicy {
    pub document: PolicyDocument,
    pub version: String,
    pub hash: String,
}

const FORBIDDEN_SECRET_FIELDS: &[&str] = &[
    "api_key", "card_number", "credential", "cpf", "password", "private_key", "secret", "ssn", "token",
];
const KNOWN_PRIVATE_REFS: &[&str] = &["verified_email"];

fn normalized(value: &str) -> String { value.trim().to_ascii_lowercase() }

fn metadata(applied: Option<&AppliedPolicy>) -> (Option<String>, Option<String>) {
    applied
        .map(|value| (Some(value.version.clone()), Some(value.hash.clone())))
        .unwrap_or((None, None))
}

fn deny(
    request_id: &str,
    code: &str,
    reason: &str,
    applied: Option<&AppliedPolicy>,
    requires_human_authorization: bool,
) -> PolicyDecision {
    let (policy_version, policy_hash) = metadata(applied);
    PolicyDecision {
        request_id: request_id.to_string(),
        decision: Decision::Deny,
        reason_code: code.to_string(),
        reason: reason.to_string(),
        allowed_fields: vec![],
        redacted_fields: vec![],
        allowed_private_refs: vec![],
        redacted_private_refs: vec![],
        policy_version,
        policy_hash,
        requires_human_authorization,
    }
}

fn valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_LEN
        && version.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
}

fn validate_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && !host.contains('/')
        && !host.contains(':')
        && !host.contains('@')
        && !host.contains(char::is_whitespace)
}

fn canonical_list(
    values: &[String],
    max_items: usize,
    max_len: usize,
    label: &str,
) -> Result<Vec<String>, String> {
    if values.len() > max_items {
        return Err(format!("policy {label} exceeds item limit"));
    }
    let mut normalized_values = BTreeSet::new();
    for raw in values {
        let value = normalized(raw);
        if value.is_empty() || value.len() > max_len {
            return Err(format!("policy {label} contains an invalid value"));
        }
        if !normalized_values.insert(value) {
            return Err(format!("policy {label} contains a duplicate normalized value"));
        }
    }
    Ok(normalized_values.into_iter().collect())
}

pub fn parse_policy_document(bytes: &[u8]) -> Result<AppliedPolicy, String> {
    if bytes.is_empty() || bytes.len() > MAX_POLICY_BYTES {
        return Err("policy document is missing or exceeds the maximum size".to_string());
    }
    let parsed: PolicyDocument = serde_json::from_slice(bytes)
        .map_err(|_| "policy document is not valid JSON".to_string())?;
    let version = parsed.version.trim().to_string();
    if !valid_version(&version) {
        return Err("policy version is missing or invalid".to_string());
    }
    if parsed.actions.is_empty() || parsed.actions.len() > MAX_ACTIONS {
        return Err("policy action count is invalid".to_string());
    }

    let mut canonical_actions = BTreeMap::new();
    for (raw_action, rule) in parsed.actions {
        let action = normalized(&raw_action);
        if action.is_empty() || action.len() > MAX_NAME_LEN || action != raw_action.trim() {
            return Err("policy action name is not canonical".to_string());
        }
        if canonical_actions.contains_key(&action) {
            return Err("policy contains duplicate normalized actions".to_string());
        }
        let purpose = normalized(&rule.purpose);
        if purpose.is_empty() || purpose.len() > MAX_NAME_LEN {
            return Err("policy purpose is invalid".to_string());
        }
        let allowed_fields = canonical_list(&rule.allowed_fields, MAX_FIELDS, MAX_NAME_LEN, "allowed_fields")?;
        if allowed_fields.iter().any(|field| FORBIDDEN_SECRET_FIELDS.contains(&field.as_str())) {
            return Err("policy attempts to allow a contract-forbidden secret field".to_string());
        }
        let allowed_hosts = canonical_list(&rule.allowed_hosts, MAX_HOSTS, MAX_HOST_LEN, "allowed_hosts")?;
        if allowed_hosts.iter().any(|host| !validate_host(host)) {
            return Err("policy contains an invalid destination host".to_string());
        }
        if !rule.requires_host && !allowed_hosts.is_empty() {
            return Err("policy cannot declare hosts for an action without egress".to_string());
        }
        if rule.requires_host && allowed_hosts.is_empty() {
            return Err("policy requires a host but declares no allowed hosts".to_string());
        }
        let allowed_private_refs = canonical_list(
            &rule.allowed_private_refs,
            MAX_PRIVATE_REFS,
            MAX_NAME_LEN,
            "allowed_private_refs",
        )?;
        if allowed_private_refs.iter().any(|value| !KNOWN_PRIVATE_REFS.contains(&value.as_str())) {
            return Err("policy attempts to enable an unknown private-data reference".to_string());
        }
        canonical_actions.insert(action, ActionPolicy {
            purpose,
            allowed_fields,
            allowed_hosts,
            allowed_private_refs,
            requires_host: rule.requires_host,
            requires_human_authorization: rule.requires_human_authorization,
        });
    }

    let document = PolicyDocument { version: version.clone(), actions: canonical_actions };
    let canonical = serde_json::to_vec(&document).map_err(|_| "failed to canonicalize policy document".to_string())?;
    let hash = hex::encode(Sha256::digest(&canonical));
    Ok(AppliedPolicy { document, version, hash })
}

pub fn evaluate_with_policy(request: &PolicyEvaluationRequest, applied: &AppliedPolicy) -> PolicyDecision {
    let request_id = request.request_id.trim();
    if request_id.is_empty() || request_id.len() > 128 {
        return deny(request_id, "INVALID_REQUEST_ID", "Request id is required and must be at most 128 characters", Some(applied), false);
    }
    if !request.agent_did.trim().starts_with("did:t3n:") {
        return deny(request_id, "INVALID_AGENT_DID", "Agent identity must be an authenticated T3N DID", Some(applied), false);
    }
    if request.resource.trim().is_empty() {
        return deny(request_id, "INVALID_RESOURCE", "Resource is required", Some(applied), false);
    }

    let action = normalized(&request.action);
    let Some(rule) = applied.document.actions.get(&action) else {
        return deny(request_id, "ACTION_NOT_ALLOWED", "Requested action is not enabled by the active policy", Some(applied), false);
    };
    let requires_human_authorization = rule.requires_human_authorization;
    if normalized(&request.purpose) != rule.purpose {
        return deny(request_id, "PURPOSE_NOT_ALLOWED", "Declared purpose does not authorize this action", Some(applied), requires_human_authorization);
    }

    let requested_fields: BTreeSet<String> = request.fields.iter().map(|field| normalized(field)).filter(|field| !field.is_empty()).collect();
    if requested_fields.iter().any(|field| FORBIDDEN_SECRET_FIELDS.contains(&field.as_str())) {
        return deny(request_id, "SECRET_DISCLOSURE_FORBIDDEN", "Direct disclosure of secrets or high-risk credentials is forbidden", Some(applied), requires_human_authorization);
    }

    let requested_private_refs: BTreeSet<String> = request.private_refs.iter().map(|value| normalized(value)).filter(|value| !value.is_empty()).collect();
    if requested_private_refs.iter().any(|value| value.contains("{{") || value.contains("}}") || value.starts_with("profile.")) {
        return deny(request_id, "RAW_PLACEHOLDER_FORBIDDEN", "Clients must use logical private-data references, not T3N placeholder strings", Some(applied), requires_human_authorization);
    }
    if requested_private_refs.iter().any(|value| !KNOWN_PRIVATE_REFS.contains(&value.as_str())) {
        return deny(request_id, "PRIVATE_REFERENCE_UNKNOWN", "Requested private-data reference is not recognized by the contract", Some(applied), requires_human_authorization);
    }

    let host = request.host.as_deref().map(normalized).filter(|value| !value.is_empty());
    if rule.requires_host {
        let Some(host) = host.as_deref() else {
            return deny(request_id, "HOST_REQUIRED", "This action requires an explicitly authorized destination host", Some(applied), requires_human_authorization);
        };
        if !validate_host(host) || !rule.allowed_hosts.iter().any(|value| value == host) {
            return deny(request_id, "HOST_NOT_ALLOWED", "Destination host is outside the active policy allowlist", Some(applied), requires_human_authorization);
        }
    } else if host.is_some() {
        return deny(request_id, "UNEXPECTED_EGRESS", "This action does not require outbound network access", Some(applied), requires_human_authorization);
    }

    let allowed_fields_set: BTreeSet<&str> = rule.allowed_fields.iter().map(String::as_str).collect();
    let mut allowed_fields = Vec::new();
    let mut redacted_fields = Vec::new();
    for field in requested_fields {
        if allowed_fields_set.contains(field.as_str()) { allowed_fields.push(field); } else { redacted_fields.push(field); }
    }

    let allowed_private_set: BTreeSet<&str> = rule.allowed_private_refs.iter().map(String::as_str).collect();
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
            "Action and requested data satisfy the active versioned policy"
        }.to_string(),
        allowed_fields,
        redacted_fields,
        allowed_private_refs,
        redacted_private_refs,
        policy_version: Some(applied.version.clone()),
        policy_hash: Some(applied.hash.clone()),
        requires_human_authorization,
    }
}

pub fn evaluate_with_policy_bytes(request: &PolicyEvaluationRequest, bytes: Option<&[u8]>) -> PolicyDecision {
    let Some(bytes) = bytes else {
        return deny(request.request_id.trim(), "POLICY_UNAVAILABLE", "Versioned operational policy is unavailable", None, false);
    };
    match parse_policy_document(bytes) {
        Ok(applied) => evaluate_with_policy(request, &applied),
        Err(_) => deny(request.request_id.trim(), "POLICY_INVALID", "Versioned operational policy is invalid", None, false),
    }
}

#[cfg(target_arch = "wasm32")]
use crate::host::{interfaces::kv_store, tenant::tenant_context};

#[cfg(target_arch = "wasm32")]
fn read_policy_bytes() -> Result<Vec<u8>, String> {
    let tid = tenant_context::tenant_did();
    let map_name = alloc::format!("z:{}:privacy-guard-policy", hex::encode(&tid));
    kv_store::get(&map_name, b"current")
        .map_err(|_| "versioned operational policy map is unavailable".to_string())?
        .ok_or_else(|| "versioned operational policy entry is missing".to_string())
}

pub fn evaluate_json(input: &[u8]) -> Result<Vec<u8>, String> {
    let request: PolicyEvaluationRequest = serde_json::from_slice(input)
        .map_err(|_| "evaluate-action: invalid JSON input".to_string())?;

    #[cfg(target_arch = "wasm32")]
    let decision = match read_policy_bytes() {
        Ok(bytes) => evaluate_with_policy_bytes(&request, Some(&bytes)),
        Err(_) => evaluate_with_policy_bytes(&request, None),
    };

    #[cfg(not(target_arch = "wasm32"))]
    let decision = evaluate_with_policy_bytes(&request, None);

    serde_json::to_vec(&decision).map_err(|_| "evaluate-action: failed to encode decision".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline_policy_json() -> Vec<u8> {
        br#"{
          "version":"2026-09-12.1",
          "actions":{
            "create-incident":{"purpose":"incident-recording","allowed_fields":["incident_id","severity","summary","source"],"allowed_hosts":[],"allowed_private_refs":[],"requires_host":false,"requires_human_authorization":false},
            "isolate-account":{"purpose":"incident-remediation","allowed_fields":["incident_id","account_id","reason"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true},
            "notify-security":{"purpose":"incident-notification","allowed_fields":["incident_id","severity","summary"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":["verified_email"],"requires_host":true,"requires_human_authorization":false},
            "revoke-credential":{"purpose":"incident-remediation","allowed_fields":["incident_id","credential_id","reason"],"allowed_hosts":["postman-echo.com","security-api.internal"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}
          }
        }"#.to_vec()
    }

    fn policy() -> AppliedPolicy { parse_policy_document(&baseline_policy_json()).unwrap() }

    fn request() -> PolicyEvaluationRequest {
        PolicyEvaluationRequest {
            request_id: "req-001".into(), agent_did: "did:t3n:agent123".into(), action: "revoke-credential".into(),
            resource: "credential:cred-42".into(), purpose: "incident-remediation".into(), host: Some("postman-echo.com".into()),
            fields: vec!["incident_id".into(), "credential_id".into(), "reason".into()], private_refs: vec![],
        }
    }

    #[test]
    fn allows_minimal_authorized_request_with_policy_metadata() {
        let applied = policy();
        let decision = evaluate_with_policy(&request(), &applied);
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.policy_version.as_deref(), Some("2026-09-12.1"));
        assert_eq!(decision.policy_hash.as_deref(), Some(applied.hash.as_str()));
        assert!(decision.requires_human_authorization);
    }

    #[test]
    fn policy_missing_or_corrupt_fails_closed() {
        assert_eq!(evaluate_with_policy_bytes(&request(), None).reason_code, "POLICY_UNAVAILABLE");
        assert_eq!(evaluate_with_policy_bytes(&request(), Some(b"not-json")).reason_code, "POLICY_INVALID");
    }

    #[test]
    fn forbidden_secret_cannot_be_enabled_by_external_policy() {
        let bytes = br#"{"version":"v1","actions":{"revoke-credential":{"purpose":"incident-remediation","allowed_fields":["incident_id","api_key"],"allowed_hosts":["postman-echo.com"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}}}"#;
        assert!(parse_policy_document(bytes).is_err());
    }

    #[test]
    fn canonical_hash_is_stable_and_changes_with_policy_content() {
        let first = policy();
        let second = policy();
        assert_eq!(first.hash, second.hash);
        let changed = baseline_policy_json().into_iter().collect::<Vec<_>>();
        let mut value: serde_json::Value = serde_json::from_slice(&changed).unwrap();
        value["actions"]["revoke-credential"]["allowed_hosts"] = serde_json::json!(["security-api.internal"]);
        let changed = parse_policy_document(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_ne!(first.hash, changed.hash);
    }

    #[test]
    fn duplicate_normalized_values_are_rejected() {
        let bytes = br#"{"version":"v1","actions":{"revoke-credential":{"purpose":"incident-remediation","allowed_fields":["reason"," REASON "],"allowed_hosts":["postman-echo.com"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}}}"#;
        assert!(parse_policy_document(bytes).is_err());
    }

    #[test]
    fn allows_verified_email_reference_only_for_notification() {
        let value = PolicyEvaluationRequest {
            request_id: "notify-1".into(), agent_did: "did:t3n:agent123".into(), action: "notify-security".into(),
            resource: "incident:42".into(), purpose: "incident-notification".into(), host: Some("postman-echo.com".into()),
            fields: vec!["incident_id".into(), "severity".into(), "summary".into()], private_refs: vec!["verified_email".into()],
        };
        let decision = evaluate_with_policy(&value, &policy());
        assert_eq!(decision.decision, Decision::Allow);
        assert_eq!(decision.allowed_private_refs, vec!["verified_email"]);
    }

    #[test]
    fn rejects_raw_or_unknown_placeholder_input() {
        let applied = policy();
        let mut raw = request(); raw.private_refs = vec!["{{profile.verified_contacts.email.value}}".into()];
        assert_eq!(evaluate_with_policy(&raw, &applied).reason_code, "RAW_PLACEHOLDER_FORBIDDEN");
        let mut unknown = request(); unknown.private_refs = vec!["private_email".into()];
        assert_eq!(evaluate_with_policy(&unknown, &applied).reason_code, "PRIVATE_REFERENCE_UNKNOWN");
    }

    #[test]
    fn redacts_valid_private_reference_when_not_needed_by_action() {
        let mut value = request(); value.private_refs = vec!["verified_email".into()];
        let decision = evaluate_with_policy(&value, &policy());
        assert_eq!(decision.decision, Decision::Redact);
        assert_eq!(decision.redacted_private_refs, vec!["verified_email"]);
    }

    #[test]
    fn invalid_json_fails_closed_before_policy_lookup() {
        assert!(evaluate_json(b"not-json").is_err());
    }
}
