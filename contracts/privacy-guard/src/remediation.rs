use crate::{authorization, policy::{self, AppliedPolicy, Decision, PolicyDecision, PolicyEvaluationRequest}};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const VERIFIED_EMAIL_MARKER: &str = "{{profile.verified_contacts.email.value}}";
const REVOKE_CREDENTIAL_ACTION: &str = "revoke-credential";
const NOTIFY_SECURITY_ACTION: &str = "notify-security";
const MAX_NORMAL_PAYLOAD_ENTRIES: usize = 16;
const MAX_NORMAL_KEY_LEN: usize = 80;
const MAX_NORMAL_VALUE_BYTES: usize = 512;
const MAX_AUTHORIZATION_PROOF_BYTES: usize = 8_192;
const MAX_OPERATION_ID_BYTES: usize = 128;
const FORBIDDEN_NORMAL_PAYLOAD_KEYS: &[&str] = &[
    "api_key", "card_number", "credential", "cpf", "password", "private_key", "secret", "ssn", "token",
];
const REVOKE_REQUIRED_NORMAL_FIELDS: &[&str] = &["incident_id", "credential_id", "reason"];
const NOTIFY_REQUIRED_NORMAL_FIELDS: &[&str] = &["incident_id", "severity", "summary"];

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationExecutionRequest {
    pub incident_id: String,
    pub action_id: String,
    pub decision_id: String,
    pub request_id: String,
    pub agent_did: String,
    pub executor_did: String,
    pub action: String,
    pub resource: String,
    pub purpose: String,
    pub approved_host: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub normal_payload: BTreeMap<String, String>,
    #[serde(default)]
    pub private_refs: Vec<String>,
    pub policy_version: String,
    pub policy_hash: String,
    pub authorization_proof: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationResult {
    pub request_id: String,
    pub status: String,
    pub http_code: u16,
    pub operation_id: Option<String>,
    pub policy_version: String,
    pub policy_hash: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PayloadMinimizationProof {
    pub must_egress_seen: bool,
    pub must_not_egress_seen: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationVerificationRequest {
    pub request_id: String,
    pub operation_id: String,
    pub action: String,
    pub expected_state: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationVerificationResult {
    pub request_id: String,
    pub status: String,
    pub observed_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_resolved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_proof: Option<PayloadMinimizationProof>,
}

pub fn execute_remediation(input: &[u8]) -> Result<Vec<u8>, String> {
    let request: RemediationExecutionRequest = serde_json::from_slice(input)
        .map_err(|_| "execute-remediation: invalid JSON input".to_string())?;
    validate_execution_request(&request)?;

    #[cfg(target_arch = "wasm32")]
    {
        let result = execute_wasm(request)?;
        return serde_json::to_vec(&result)
            .map_err(|_| "execute-remediation: failed to encode result".to_string());
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = request;
        Err("execute-remediation is only implemented on the wasm32 target".to_string())
    }
}

pub fn verify_remediation(input: &[u8]) -> Result<Vec<u8>, String> {
    let request: RemediationVerificationRequest = serde_json::from_slice(input)
        .map_err(|_| "verify-remediation: invalid JSON input".to_string())?;
    validate_verification_request(&request)?;

    #[cfg(target_arch = "wasm32")]
    {
        let result = verify_wasm(request)?;
        return serde_json::to_vec(&result)
            .map_err(|_| "verify-remediation: failed to encode result".to_string());
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = request;
        Err("verify-remediation is only implemented on the wasm32 target".to_string())
    }
}

fn normalized(value: &str) -> String { value.trim().to_ascii_lowercase() }

fn valid_normal_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_NORMAL_KEY_LEN || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes.iter().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn required_normal_fields(action: &str) -> Result<&'static [&'static str], String> {
    match action {
        REVOKE_CREDENTIAL_ACTION => Ok(REVOKE_REQUIRED_NORMAL_FIELDS),
        NOTIFY_SECURITY_ACTION => Ok(NOTIFY_REQUIRED_NORMAL_FIELDS),
        _ => Err("protected remediation executor is not implemented for this action".to_string()),
    }
}

fn validate_normal_payload(request: &RemediationExecutionRequest) -> Result<(), String> {
    if request.normal_payload.is_empty() || request.normal_payload.len() > MAX_NORMAL_PAYLOAD_ENTRIES {
        return Err("trusted normal payload is missing or exceeds the item limit".to_string());
    }
    let requested_fields: BTreeSet<String> = request.fields.iter().map(|field| normalized(field)).collect();
    for (key, value) in &request.normal_payload {
        if !valid_normal_key(key) || key != &normalized(key) {
            return Err("trusted normal payload contains an invalid key".to_string());
        }
        if FORBIDDEN_NORMAL_PAYLOAD_KEYS.contains(&key.as_str()) {
            return Err("trusted normal payload contains a forbidden secret field".to_string());
        }
        if value.trim().is_empty() || value.as_bytes().len() > MAX_NORMAL_VALUE_BYTES {
            return Err("trusted normal payload contains an invalid value".to_string());
        }
        if !requested_fields.contains(key) {
            return Err("trusted normal payload contains a field that was not requested".to_string());
        }
    }
    Ok(())
}

fn validate_execution_request(request: &RemediationExecutionRequest) -> Result<(), String> {
    match request.action.as_str() {
        REVOKE_CREDENTIAL_ACTION => {
            if request.purpose != "incident-remediation" || !request.private_refs.is_empty() {
                return Err("revoke-credential executor received an invalid closed execution contract".to_string());
            }
        }
        NOTIFY_SECURITY_ACTION => {
            if request.purpose != "incident-notification"
                || request.private_refs.len() != 1
                || request.private_refs[0] != "verified_email"
            {
                return Err("notify-security requires exactly the logical private reference verified_email for incident-notification".to_string());
            }
        }
        _ => return Err("protected remediation executor is not implemented for this action".to_string()),
    }
    for (name, value) in [
        ("incident_id", request.incident_id.as_str()),
        ("action_id", request.action_id.as_str()),
        ("decision_id", request.decision_id.as_str()),
        ("request_id", request.request_id.as_str()),
        ("agent_did", request.agent_did.as_str()),
        ("executor_did", request.executor_did.as_str()),
        ("resource", request.resource.as_str()),
        ("purpose", request.purpose.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("{name} is required for protected remediation"));
        }
    }
    if !request.executor_did.starts_with("did:t3n:") {
        return Err("protected executor DID is invalid".to_string());
    }
    if request.authorization_proof.is_empty() || request.authorization_proof.len() > MAX_AUTHORIZATION_PROOF_BYTES {
        return Err("one-time authorization proof is required for protected remediation".to_string());
    }
    canonicalize_hostname(&request.approved_host)?;
    validate_normal_payload(request)?;
    Ok(())
}

fn expected_state_for_action(action: &str) -> Result<&'static str, String> {
    match action {
        REVOKE_CREDENTIAL_ACTION => Ok("REVOKED"),
        NOTIFY_SECURITY_ACTION => Ok("DELIVERED"),
        _ => Err("verification action is not supported".to_string()),
    }
}

fn valid_operation_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_OPERATION_ID_BYTES
        && bytes[0].is_ascii_alphanumeric()
        && bytes.iter().all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
}

fn validate_verification_request(request: &RemediationVerificationRequest) -> Result<(), String> {
    if request.request_id.trim().is_empty() || request.operation_id.trim().is_empty() {
        return Err("verification identifiers are required".to_string());
    }
    if !valid_operation_id(&request.operation_id) {
        return Err("verification operation id is not a safe opaque identifier".to_string());
    }
    if request.expected_state != expected_state_for_action(&request.action)? {
        return Err("verification expected_state does not match the remediation action".to_string());
    }
    Ok(())
}

fn validate_policy_binding(request: &RemediationExecutionRequest, applied: &AppliedPolicy) -> Result<(), String> {
    if request.policy_version.trim().is_empty() || request.policy_hash.len() != 64 {
        return Err("approved policy metadata is required for remediation".to_string());
    }
    if request.policy_version != applied.version || request.policy_hash != applied.hash {
        return Err("active policy changed after authorization; remediation must be re-evaluated".to_string());
    }
    Ok(())
}

fn canonicalize_hostname(value: &str) -> Result<String, String> {
    let host = value.trim();
    if host.is_empty() || host.len() > 253 || !host.is_ascii() || host.ends_with('.')
        || host.contains("://") || host.contains('/') || host.contains('@') || host.contains(':')
        || host.contains('?') || host.contains('#') {
        return Err("approved remediation destination is not a valid hostname".to_string());
    }
    let canonical = host.to_ascii_lowercase();
    for label in canonical.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
            || !label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
            return Err("approved remediation destination is not a valid hostname".to_string());
        }
    }
    Ok(canonical)
}

fn extract_https_host(url: &str) -> Result<String, String> {
    let rest = url.strip_prefix("https://").ok_or("security endpoint must use https")?;
    let host = rest.split('/').next().unwrap_or("");
    canonicalize_hostname(host).map_err(|_| "security endpoint contains an invalid host".to_string())
}

fn ensure_execution_destination(approved_host: &str, actual_host: &str) -> Result<String, String> {
    let approved = canonicalize_hostname(approved_host)?;
    let actual = canonicalize_hostname(actual_host)
        .map_err(|_| "security endpoint contains an invalid host".to_string())?;
    if approved != actual {
        return Err("EXECUTION_DESTINATION_CHANGED".to_string());
    }
    Ok(actual)
}

fn profile_marker(logical_ref: &str) -> Result<&'static str, String> {
    match logical_ref {
        "verified_email" => Ok(VERIFIED_EMAIL_MARKER),
        _ => Err("private-data reference is not mapped by this contract".to_string()),
    }
}

fn extract_operation_id(payload: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|value| value.get("operation_id").and_then(|entry| entry.as_str()).filter(|entry| valid_operation_id(entry)).map(str::to_string))
}

fn extract_payload_proof(parsed: &serde_json::Value) -> Option<PayloadMinimizationProof> {
    let proof = parsed.get("payload_proof")?.as_object()?;
    Some(PayloadMinimizationProof {
        must_egress_seen: proof.get("must_egress_seen")?.as_bool()?,
        must_not_egress_seen: proof.get("must_not_egress_seen")?.as_bool()?,
    })
}

fn verification_from_payload(request: &RemediationVerificationRequest, payload: &[u8]) -> RemediationVerificationResult {
    let parsed = serde_json::from_slice::<serde_json::Value>(payload).ok();
    let observed_operation = parsed.as_ref()
        .and_then(|value| value.get("operation_id"))
        .and_then(|value| value.as_str());
    let observed_state = parsed.as_ref()
        .and_then(|value| value.get("state"))
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let recipient_resolved = parsed.as_ref()
        .and_then(|value| value.get("recipient_resolved"))
        .and_then(|value| value.as_bool());
    let payload_proof = parsed.as_ref().and_then(extract_payload_proof);
    let private_resolution_verified = request.action != NOTIFY_SECURITY_ACTION || recipient_resolved == Some(true);
    let verified = observed_operation == Some(request.operation_id.as_str())
        && observed_state.as_deref() == Some(request.expected_state.as_str())
        && private_resolution_verified;
    RemediationVerificationResult {
        request_id: request.request_id.clone(),
        status: if verified { "VERIFIED" } else { "UNVERIFIED" }.to_string(),
        observed_state,
        recipient_resolved,
        payload_proof,
    }
}

fn original_policy_request(request: &RemediationExecutionRequest, host: &str) -> PolicyEvaluationRequest {
    PolicyEvaluationRequest {
        request_id: request.request_id.clone(),
        agent_did: request.agent_did.clone(),
        action: request.action.clone(),
        resource: request.resource.clone(),
        purpose: request.purpose.clone(),
        host: Some(host.to_string()),
        fields: request.fields.clone(),
        private_refs: request.private_refs.clone(),
    }
}

fn minimized_payload(
    request: &RemediationExecutionRequest,
    decision: &PolicyDecision,
) -> Result<BTreeMap<String, String>, String> {
    if decision.decision == Decision::Deny {
        return Err(format!("remediation denied: {}", decision.reason_code));
    }
    let allowed: BTreeSet<&str> = decision.allowed_fields.iter().map(String::as_str).collect();
    for required in required_normal_fields(&request.action)? {
        if !allowed.contains(required) {
            return Err(format!("remediation denied: required field {required} was not allowed"));
        }
        if !request.normal_payload.contains_key(*required) {
            return Err(format!("remediation denied: trusted payload is missing required field {required}"));
        }
    }
    Ok(request.normal_payload.iter()
        .filter(|(key, _)| allowed.contains(key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect())
}

fn build_minimized_egress(
    request: &RemediationExecutionRequest,
    applied_policy: &AppliedPolicy,
    host: &str,
) -> Result<(serde_json::Value, PolicyEvaluationRequest), String> {
    validate_execution_request(request)?;
    validate_policy_binding(request, applied_policy)?;

    let requested = original_policy_request(request, host);
    let initial_decision = policy::evaluate_with_policy(&requested, applied_policy);
    let normal_payload = minimized_payload(request, &initial_decision)?;
    if request.action == NOTIFY_SECURITY_ACTION
        && initial_decision.allowed_private_refs.as_slice() != ["verified_email"]
    {
        return Err("remediation denied: verified_email was not allowed for private notification".to_string());
    }

    let effective_request = PolicyEvaluationRequest {
        request_id: requested.request_id.clone(),
        agent_did: requested.agent_did.clone(),
        action: requested.action.clone(),
        resource: requested.resource.clone(),
        purpose: requested.purpose.clone(),
        host: requested.host.clone(),
        fields: initial_decision.allowed_fields.clone(),
        private_refs: initial_decision.allowed_private_refs.clone(),
    };
    let effective_decision = policy::evaluate_with_policy(&effective_request, applied_policy);
    if effective_decision.decision != Decision::Allow {
        return Err(format!("remediation denied after minimization: {}", effective_decision.reason_code));
    }

    let mut body = serde_json::json!({
        "request_id": request.request_id,
        "action": request.action,
        "resource": request.resource,
        "purpose": request.purpose
    });
    let object = body.as_object_mut().ok_or("failed to construct remediation payload")?;
    for (key, value) in normal_payload {
        object.insert(key, serde_json::Value::String(value));
    }
    for logical_ref in &effective_request.private_refs {
        let marker = profile_marker(logical_ref)?;
        match logical_ref.as_str() {
            "verified_email" => { object.insert("recipient".to_string(), serde_json::Value::String(marker.to_string())); }
            _ => return Err("private-data reference has no output mapping".to_string()),
        }
    }
    Ok((body, effective_request))
}

#[cfg(target_arch = "wasm32")]
use crate::host::{
    interfaces::{http_with_placeholders as hwp, kv_store, logging},
    tenant::tenant_context,
};

#[cfg(target_arch = "wasm32")]
fn read_current_policy() -> Result<AppliedPolicy, String> {
    let tid = tenant_context::tenant_did();
    let map_name = alloc::format!("z:{}:privacy-guard-policy", hex::encode(&tid));
    let bytes = kv_store::get(&map_name, b"current")
        .map_err(|_| "versioned operational policy map is unavailable".to_string())?
        .ok_or_else(|| "versioned operational policy entry is missing".to_string())?;
    policy::parse_policy_document(&bytes).map_err(|_| "versioned operational policy is invalid".to_string())
}

#[cfg(target_arch = "wasm32")]
fn execute_wasm(request: RemediationExecutionRequest) -> Result<RemediationResult, String> {
    validate_execution_request(&request)?;
    let approved_host = canonicalize_hostname(&request.approved_host)?;

    authorization::verify_and_consume(&request)?;

    let applied_policy = read_current_policy()?;
    validate_policy_binding(&request, &applied_policy)?;
    let api_url = read_secret("security_api_url")?;
    let resolved_host = extract_https_host(&api_url)?;
    let host = ensure_execution_destination(&approved_host, &resolved_host)?;
    let (body, effective_request) = build_minimized_egress(&request, &applied_policy, &host)?;

    let api_key = read_secret("security_api_key")?;
    let _ = logging::info("Executing T3N-minimized remediation payload after one-time authorization proof verification");
    let response = hwp::call(&hwp::Request {
        method: hwp::Verb::Post,
        url: api_url,
        headers: Some(vec![
            ("Authorization".to_string(), alloc::format!("Bearer {api_key}")),
            ("Accept".to_string(), "application/json".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Idempotency-Key".to_string(), effective_request.request_id.clone()),
        ]),
        payload: Some(serde_json::to_vec(&body).map_err(|_| "failed to encode remediation request".to_string())?),
    })
    .map_err(format_http_error)?;

    if !(200..300).contains(&response.code) {
        return Err(alloc::format!("remediation upstream returned HTTP {}", response.code));
    }

    Ok(RemediationResult {
        request_id: effective_request.request_id,
        status: "PENDING_VERIFICATION".to_string(),
        http_code: response.code,
        operation_id: extract_operation_id(&response.payload),
        policy_version: applied_policy.version,
        policy_hash: applied_policy.hash,
    })
}

#[cfg(target_arch = "wasm32")]
fn verify_wasm(request: RemediationVerificationRequest) -> Result<RemediationVerificationResult, String> {
    let verification_url = read_secret("security_verification_url")?;
    let api_key = read_secret("security_api_key")?;
    let _ = extract_https_host(&verification_url)?;
    let body = serde_json::json!({
        "request_id": request.request_id,
        "operation_id": request.operation_id,
        "action": request.action,
        "expected_state": request.expected_state
    });
    let _ = logging::info("Verifying privacy-guard remediation through independent read-back");
    let response = hwp::call(&hwp::Request {
        method: hwp::Verb::Post,
        url: verification_url,
        headers: Some(vec![
            ("Authorization".to_string(), alloc::format!("Bearer {api_key}")),
            ("Accept".to_string(), "application/json".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ]),
        payload: Some(serde_json::to_vec(&body).map_err(|_| "failed to encode verification request".to_string())?),
    }).map_err(format_http_error)?;

    if !(200..300).contains(&response.code) {
        return Err(alloc::format!("verification upstream returned HTTP {}", response.code));
    }
    Ok(verification_from_payload(&request, &response.payload))
}

#[cfg(target_arch = "wasm32")]
fn read_secret(key: &str) -> Result<String, String> {
    let tid = tenant_context::tenant_did();
    let map_name = alloc::format!("z:{}:secrets", hex::encode(&tid));
    let bytes = kv_store::get(&map_name, key.as_bytes())
        .map_err(|_| "private secret map is unavailable".to_string())?
        .ok_or_else(|| alloc::format!("required private configuration {key} is missing"))?;
    String::from_utf8(bytes).map_err(|_| alloc::format!("private configuration {key} is not valid UTF-8"))
}

#[cfg(target_arch = "wasm32")]
fn format_http_error(error: hwp::HttpError) -> String {
    match error {
        hwp::HttpError::EgressDenied(host) => alloc::format!("egress denied for host {host}"),
        hwp::HttpError::PlaceholderDenied(_) => "profile placeholder resolution was denied".to_string(),
        hwp::HttpError::PlaceholderUnknown(_) => "required verified profile value is unavailable".to_string(),
        hwp::HttpError::PlaceholderNoUserContext => "no user context for placeholder resolution".to_string(),
        hwp::HttpError::UpstreamError(_) => "upstream transport failed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applied_policy() -> AppliedPolicy {
        let mut actions = BTreeMap::new();
        actions.insert(REVOKE_CREDENTIAL_ACTION.to_string(), policy::ActionPolicy {
            purpose: "incident-remediation".into(),
            allowed_fields: vec!["credential_id".into(), "incident_id".into(), "reason".into()],
            allowed_hosts: vec!["postman-echo.com".into()],
            allowed_private_refs: vec![],
            requires_host: true,
            requires_human_authorization: true,
        });
        actions.insert(NOTIFY_SECURITY_ACTION.to_string(), policy::ActionPolicy {
            purpose: "incident-notification".into(),
            allowed_fields: vec!["incident_id".into(), "severity".into(), "summary".into()],
            allowed_hosts: vec!["postman-echo.com".into()],
            allowed_private_refs: vec!["verified_email".into()],
            requires_host: true,
            requires_human_authorization: true,
        });
        AppliedPolicy {
            document: policy::PolicyDocument { version: "2026-09-12.1".into(), actions },
            version: "2026-09-12.1".into(),
            hash: "a".repeat(64),
        }
    }

    fn normal_payload() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("incident_id".into(), "inc-demo-001".into()),
            ("credential_id".into(), "cred-demo-001".into()),
            ("reason".into(), "suspected compromise".into()),
        ])
    }

    fn notification_normal_payload() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("incident_id".into(), "inc-demo-001".into()),
            ("severity".into(), "critical".into()),
            ("summary".into(), "synthetic security incident".into()),
        ])
    }

    fn execution_request() -> RemediationExecutionRequest {
        RemediationExecutionRequest {
            incident_id: "incident-1".into(), action_id: "action-1".into(), decision_id: "decision-1".into(),
            request_id: "r1".into(), agent_did: "did:t3n:a".into(), executor_did: "did:t3n:executor".into(),
            action: REVOKE_CREDENTIAL_ACTION.into(), resource: "credential:test".into(), purpose: "incident-remediation".into(), approved_host: "postman-echo.com".into(),
            fields: vec!["incident_id".into(), "credential_id".into(), "reason".into()],
            normal_payload: normal_payload(), private_refs: vec![], policy_version: "2026-09-12.1".into(), policy_hash: "a".repeat(64),
            authorization_proof: "v2.placeholder.signature".into(),
        }
    }

    fn notification_execution_request() -> RemediationExecutionRequest {
        RemediationExecutionRequest {
            request_id: "r2".into(), action: NOTIFY_SECURITY_ACTION.into(), resource: "incident:test".into(), purpose: "incident-notification".into(),
            fields: vec!["incident_id".into(), "severity".into(), "summary".into()], normal_payload: notification_normal_payload(),
            private_refs: vec!["verified_email".into()], ..execution_request()
        }
    }

    #[test]
    fn maps_only_verified_email_to_the_t3n_profile_marker() {
        assert_eq!(profile_marker("verified_email").unwrap(), VERIFIED_EMAIL_MARKER);
        assert!(profile_marker("{{profile.verified_contacts.email.value}}").is_err());
        assert!(profile_marker("unknown_private_value").is_err());
    }

    #[test]
    fn notify_security_requires_the_exact_logical_private_reference_and_purpose() {
        assert!(validate_execution_request(&notification_execution_request()).is_ok());
        let missing_ref = RemediationExecutionRequest { private_refs: vec![], ..notification_execution_request() };
        assert!(validate_execution_request(&missing_ref).is_err());
        let literal_marker = RemediationExecutionRequest { private_refs: vec![VERIFIED_EMAIL_MARKER.into()], ..notification_execution_request() };
        assert!(validate_execution_request(&literal_marker).is_err());
        let wrong_purpose = RemediationExecutionRequest { purpose: "analytics".into(), ..notification_execution_request() };
        assert!(validate_execution_request(&wrong_purpose).is_err());
    }

    #[test]
    fn remediation_requires_the_exact_authorized_policy_version_and_hash() {
        let applied = applied_policy();
        let valid = RemediationExecutionRequest { policy_version: applied.version.clone(), policy_hash: applied.hash.clone(), ..execution_request() };
        assert!(validate_policy_binding(&valid, &applied).is_ok());
        let changed = RemediationExecutionRequest { policy_hash: "b".repeat(64), ..valid };
        assert!(validate_policy_binding(&changed, &applied).is_err());
    }

    #[test]
    fn approved_destination_must_match_the_kv_resolved_execution_host() {
        assert_eq!(ensure_execution_destination("postman-echo.com", "postman-echo.com").unwrap(), "postman-echo.com");
        assert_eq!(ensure_execution_destination("POSTMAN-ECHO.COM", "postman-echo.com").unwrap(), "postman-echo.com");
        assert_eq!(ensure_execution_destination("security-a.example", "security-b.example").unwrap_err(), "EXECUTION_DESTINATION_CHANGED");
        assert_eq!(extract_https_host("https://postman-echo.com/post").unwrap(), "postman-echo.com");
        assert!(extract_https_host("https://postman-echo.com:443/post").is_err());
        assert!(canonicalize_hostname("https://postman-echo.com/post").is_err());
    }

    #[test]
    fn exact_allowed_normal_payload_is_materialized_for_egress() {
        let request = execution_request();
        let (body, effective) = build_minimized_egress(&request, &applied_policy(), "postman-echo.com").unwrap();
        assert_eq!(effective.fields, vec!["credential_id", "incident_id", "reason"]);
        assert_eq!(body.get("incident_id").and_then(|value| value.as_str()), Some("inc-demo-001"));
        assert_eq!(body.get("credential_id").and_then(|value| value.as_str()), Some("cred-demo-001"));
        assert_eq!(body.get("reason").and_then(|value| value.as_str()), Some("suspected compromise"));
    }

    #[test]
    fn notification_combines_minimized_normal_values_with_private_placeholder_only_inside_egress() {
        let request = notification_execution_request();
        let (body, effective) = build_minimized_egress(&request, &applied_policy(), "postman-echo.com").unwrap();
        assert_eq!(effective.private_refs, vec!["verified_email"]);
        assert_eq!(body.get("incident_id").and_then(|value| value.as_str()), Some("inc-demo-001"));
        assert_eq!(body.get("severity").and_then(|value| value.as_str()), Some("critical"));
        assert_eq!(body.get("summary").and_then(|value| value.as_str()), Some("synthetic security incident"));
        assert_eq!(body.get("recipient").and_then(|value| value.as_str()), Some(VERIFIED_EMAIL_MARKER));
    }

    #[test]
    fn redacted_normal_value_never_enters_the_egress_body() {
        let mut request = execution_request();
        request.fields.push("employee_department".into());
        request.normal_payload.insert("employee_department".into(), "finance".into());
        let initial = policy::evaluate_with_policy(&original_policy_request(&request, "postman-echo.com"), &applied_policy());
        assert_eq!(initial.decision, Decision::Redact);
        assert_eq!(initial.redacted_fields, vec!["employee_department"]);

        let (body, effective) = build_minimized_egress(&request, &applied_policy(), "postman-echo.com").unwrap();
        assert_eq!(policy::evaluate_with_policy(&effective, &applied_policy()).decision, Decision::Allow);
        assert!(body.get("employee_department").is_none());
        assert_eq!(body.get("reason").and_then(|value| value.as_str()), Some("suspected compromise"));
    }

    #[test]
    fn secret_or_unrequested_normal_payload_fields_fail_before_egress() {
        let mut secret = execution_request();
        secret.fields.push("api_key".into());
        secret.normal_payload.insert("api_key".into(), "synthetic-secret-must-not-egress".into());
        assert!(validate_execution_request(&secret).unwrap_err().contains("forbidden secret field"));

        let mut unrequested = execution_request();
        unrequested.normal_payload.insert("employee_department".into(), "finance".into());
        assert!(validate_execution_request(&unrequested).unwrap_err().contains("was not requested"));
    }

    #[test]
    fn bounded_payload_proof_exposes_only_booleans() {
        let request = RemediationVerificationRequest { request_id: "r1".into(), operation_id: "op-1".into(), action: REVOKE_CREDENTIAL_ACTION.into(), expected_state: "REVOKED".into() };
        let sentinel = "SENTINEL_MUST_NOT_LEAK_BACK";
        let payload = serde_json::json!({
            "operation_id": "op-1",
            "state": "REVOKED",
            "payload_proof": { "must_egress_seen": true, "must_not_egress_seen": false },
            "debug": sentinel
        });
        let result = verification_from_payload(&request, &serde_json::to_vec(&payload).unwrap());
        assert_eq!(result.payload_proof, Some(PayloadMinimizationProof { must_egress_seen: true, must_not_egress_seen: false }));
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains(sentinel));
    }

    #[test]
    fn execution_rejects_actions_without_a_verified_completion_contract_before_egress() {
        for action in ["isolate-account", "create-incident"] {
            let input = serde_json::to_vec(&RemediationExecutionRequest { action: action.into(), ..execution_request() }).unwrap();
            let error = execute_remediation(&input).unwrap_err();
            assert_eq!(error, "protected remediation executor is not implemented for this action");
        }
    }

    #[test]
    fn execution_without_approved_destination_fails_closed() {
        let input = serde_json::to_vec(&RemediationExecutionRequest { approved_host: "".into(), ..execution_request() }).unwrap();
        assert!(execute_remediation(&input).unwrap_err().contains("approved remediation destination"));
    }

    #[test]
    fn execution_without_one_time_authorization_proof_fails_closed() {
        let input = serde_json::to_vec(&RemediationExecutionRequest { authorization_proof: "".into(), ..execution_request() }).unwrap();
        assert!(execute_remediation(&input).unwrap_err().contains("one-time authorization proof"));
    }

    #[test]
    fn verification_expected_state_is_closed_per_action() {
        let revoke = RemediationVerificationRequest { request_id: "r1".into(), operation_id: "op-1".into(), action: REVOKE_CREDENTIAL_ACTION.into(), expected_state: "REVOKED".into() };
        assert!(validate_verification_request(&revoke).is_ok());
        let notify = RemediationVerificationRequest { request_id: "r2".into(), operation_id: "op-2".into(), action: NOTIFY_SECURITY_ACTION.into(), expected_state: "DELIVERED".into() };
        assert!(validate_verification_request(&notify).is_ok());
        let mismatched = RemediationVerificationRequest { expected_state: "REVOKED".into(), ..notify };
        assert!(validate_verification_request(&mismatched).is_err());
        let private_value_as_operation_id = RemediationVerificationRequest { operation_id: "private@example.test".into(), ..revoke };
        assert!(validate_verification_request(&private_value_as_operation_id).is_err());
    }

    #[test]
    fn independent_readback_must_match_operation_state_and_private_resolution() {
        let revoke = RemediationVerificationRequest { request_id: "r1".into(), operation_id: "op-1".into(), action: REVOKE_CREDENTIAL_ACTION.into(), expected_state: "REVOKED".into() };
        let verified = verification_from_payload(&revoke, br#"{"operation_id":"op-1","state":"REVOKED","secret":"do-not-return"}"#);
        assert_eq!(verified.status, "VERIFIED");
        assert_eq!(verified.observed_state.as_deref(), Some("REVOKED"));
        assert!(verified.payload_proof.is_none());

        let notify = RemediationVerificationRequest { request_id: "r2".into(), operation_id: "op-2".into(), action: NOTIFY_SECURITY_ACTION.into(), expected_state: "DELIVERED".into() };
        let delivered = verification_from_payload(&notify, br#"{"operation_id":"op-2","state":"DELIVERED","recipient_resolved":true,"recipient":"private@example.test"}"#);
        assert_eq!(delivered.status, "VERIFIED");
        assert_eq!(delivered.recipient_resolved, Some(true));
        let unresolved = verification_from_payload(&notify, br#"{"operation_id":"op-2","state":"DELIVERED","recipient_resolved":false}"#);
        assert_eq!(unresolved.status, "UNVERIFIED");
        let serialized = serde_json::to_string(&delivered).unwrap();
        assert!(!serialized.contains('@'));
        assert!(!serialized.contains(VERIFIED_EMAIL_MARKER));
    }

    #[test]
    fn native_execution_never_simulates_secret_egress() {
        let input = serde_json::to_vec(&execution_request()).unwrap();
        assert!(execute_remediation(&input).unwrap_err().contains("only implemented on the wasm32 target"));
        let notification = serde_json::to_vec(&notification_execution_request()).unwrap();
        assert!(execute_remediation(&notification).unwrap_err().contains("only implemented on the wasm32 target"));
    }

    #[test] fn malformed_input_fails_closed() { assert!(execute_remediation(b"bad").is_err()); }

    #[test]
    fn reflected_upstream_secret_or_pii_is_not_exposed_by_result_schema() {
        let sentinel = "SYNTHETIC_REFLECTED_PRIVATE_VALUE";
        let payload = serde_json::json!({ "operation_id": "operation-123", "headers": { "authorization": sentinel }, "body": sentinel, "recipient": sentinel });
        let result = RemediationResult {
            request_id: "r2".into(), status: "PENDING_VERIFICATION".into(), http_code: 200,
            operation_id: extract_operation_id(&serde_json::to_vec(&payload).unwrap()),
            policy_version: "2026-09-12.1".into(), policy_hash: "a".repeat(64),
        };
        let serialized = serde_json::to_string(&result).unwrap();
        assert_eq!(result.operation_id.as_deref(), Some("operation-123"));
        assert!(!serialized.contains(sentinel));
        assert!(!serialized.to_ascii_lowercase().contains("recipient"));

        let smuggled = serde_json::json!({ "operation_id": "private@example.test", "state": "DELIVERED" });
        assert_eq!(extract_operation_id(&serde_json::to_vec(&smuggled).unwrap()), None);
    }

    #[test] fn malformed_upstream_body_does_not_escape_raw_content() { assert_eq!(extract_operation_id(b"not-json"), None); }
}
