use crate::policy::{self, Decision, PolicyEvaluationRequest};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationExecutionRequest {
    pub request_id: String,
    pub agent_did: String,
    pub action: String,
    pub resource: String,
    pub purpose: String,
    #[serde(default)]
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RemediationResult {
    pub request_id: String,
    pub status: String,
    pub http_code: u16,
    pub operation_id: Option<String>,
}

pub fn execute_remediation(input: &[u8]) -> Result<Vec<u8>, String> {
    let request: RemediationExecutionRequest = serde_json::from_slice(input)
        .map_err(|_| "execute-remediation: invalid JSON input".to_string())?;

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

fn extract_operation_id(payload: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(payload)
        .ok()
        .and_then(|value| {
            value
                .get("operation_id")
                .and_then(|entry| entry.as_str())
                .map(str::to_string)
        })
}

#[cfg(target_arch = "wasm32")]
use crate::host::{
    interfaces::{http_with_placeholders as hwp, kv_store, logging},
    tenant::tenant_context,
};

#[cfg(target_arch = "wasm32")]
fn execute_wasm(request: RemediationExecutionRequest) -> Result<RemediationResult, String> {
    let api_url = read_secret("security_api_url")?;
    let host = extract_https_host(&api_url)?;
    let policy_request = PolicyEvaluationRequest {
        request_id: request.request_id.clone(),
        agent_did: request.agent_did,
        action: request.action.clone(),
        resource: request.resource.clone(),
        purpose: request.purpose.clone(),
        host: Some(host.to_string()),
        fields: request.fields,
    };
    let decision = policy::evaluate(&policy_request);
    if decision.decision != Decision::Allow {
        return Err(alloc::format!("remediation denied: {}", decision.reason_code));
    }

    let api_key = read_secret("security_api_key")?;
    let body = serde_json::json!({
        "request_id": request.request_id,
        "action": request.action,
        "resource": request.resource,
        "purpose": request.purpose
    });
    let _ = logging::info("Executing approved privacy-guard remediation");
    let response = hwp::call(&hwp::Request {
        method: hwp::Verb::Post,
        url: api_url,
        headers: Some(vec![
            ("Authorization".to_string(), alloc::format!("Bearer {api_key}")),
            ("Accept".to_string(), "application/json".to_string()),
        ]),
        payload: Some(
            serde_json::to_vec(&body)
                .map_err(|_| "failed to encode remediation request".to_string())?,
        ),
    })
    .map_err(format_http_error)?;

    if !(200..300).contains(&response.code) {
        return Err(alloc::format!(
            "remediation upstream returned HTTP {}",
            response.code
        ));
    }

    Ok(RemediationResult {
        request_id: policy_request.request_id,
        status: "COMPLETED".to_string(),
        http_code: response.code,
        operation_id: extract_operation_id(&response.payload),
    })
}

#[cfg(target_arch = "wasm32")]
fn read_secret(key: &str) -> Result<String, String> {
    let tid = tenant_context::tenant_did();
    let map_name = alloc::format!("z:{}:secrets", hex::encode(&tid));
    let bytes = kv_store::get(&map_name, key.as_bytes())
        .map_err(|_| "private secret map is unavailable".to_string())?
        .ok_or_else(|| alloc::format!("required private configuration {key} is missing"))?;
    String::from_utf8(bytes)
        .map_err(|_| alloc::format!("private configuration {key} is not valid UTF-8"))
}

#[cfg(target_arch = "wasm32")]
fn extract_https_host(url: &str) -> Result<&str, String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("security_api_url must use https")?;
    let host = rest.split('/').next().unwrap_or("");
    if host.is_empty() || host.contains('@') || host.contains(':') {
        return Err("security_api_url contains an invalid host".to_string());
    }
    Ok(host)
}

#[cfg(target_arch = "wasm32")]
fn format_http_error(error: hwp::HttpError) -> String {
    match error {
        hwp::HttpError::EgressDenied(host) => alloc::format!("egress denied for host {host}"),
        hwp::HttpError::PlaceholderDenied(marker) => {
            alloc::format!("placeholder not permitted: {marker}")
        }
        hwp::HttpError::PlaceholderUnknown(field) => {
            alloc::format!("profile field unavailable: {field}")
        }
        hwp::HttpError::PlaceholderNoUserContext => {
            "no user context for placeholder resolution".to_string()
        }
        hwp::HttpError::UpstreamError(_) => {
            "remediation upstream transport failed".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_execution_never_simulates_secret_egress() {
        let input = serde_json::to_vec(&RemediationExecutionRequest {
            request_id: "r1".into(),
            agent_did: "did:t3n:a".into(),
            action: "revoke-credential".into(),
            resource: "credential:test".into(),
            purpose: "incident-remediation".into(),
            fields: vec!["incident_id".into(), "credential_id".into(), "reason".into()],
        })
        .unwrap();
        assert!(execute_remediation(&input)
            .unwrap_err()
            .contains("only implemented on the wasm32 target"));
    }

    #[test]
    fn malformed_input_fails_closed() {
        assert!(execute_remediation(b"bad").is_err());
    }

    #[test]
    fn reflected_upstream_secret_is_not_exposed_by_result_schema() {
        let sentinel = "SYNTHETIC_REFLECTED_SECRET";
        let payload = serde_json::json!({
            "operation_id": "operation-123",
            "headers": { "authorization": sentinel },
            "body": sentinel
        });
        let payload = serde_json::to_vec(&payload).unwrap();
        let result = RemediationResult {
            request_id: "r2".into(),
            status: "COMPLETED".into(),
            http_code: 200,
            operation_id: extract_operation_id(&payload),
        };
        let serialized = serde_json::to_string(&result).unwrap();

        assert_eq!(result.operation_id.as_deref(), Some("operation-123"));
        assert!(!serialized.contains(sentinel));
        assert!(!serialized.to_ascii_lowercase().contains("authorization"));
    }

    #[test]
    fn malformed_upstream_body_does_not_escape_raw_content() {
        assert_eq!(extract_operation_id(b"not-json"), None);
    }
}
