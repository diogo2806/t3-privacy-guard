use crate::remediation::RemediationExecutionRequest;
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine as _};
use ed25519_dalek::{pkcs8::DecodePublicKey, Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const TOKEN_VERSION: &str = "v2";
const MAX_TOKEN_BYTES: usize = 8_192;
const MAX_CAPABILITY_LIFETIME_MS: u64 = 300_000;
const CLOCK_SKEW_MS: u64 = 5_000;
#[cfg(target_arch = "wasm32")]
const REPLAY_BUCKET_MS: u64 = 60_000;
#[cfg(target_arch = "wasm32")]
const REPLAY_BUCKET_SLOTS: u64 = 8;
#[cfg(target_arch = "wasm32")]
const MAX_REPLAY_ENTRIES_PER_BUCKET: usize = 1_024;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationClaims {
    incident_id: String,
    action_id: String,
    request_id: String,
    decision_id: String,
    action: String,
    resource: String,
    purpose: String,
    approved_host: String,
    fields_hash: String,
    normal_payload_hash: String,
    private_refs_hash: String,
    policy_version: String,
    policy_hash: String,
    executor_did: String,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Deserialize, Serialize)]
struct ReplayEntry {
    nonce_hash: String,
    expires_at: u64,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
struct ReplayBucket {
    epoch: u64,
    entries: Vec<ReplayEntry>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn list_hash(values: &[String]) -> Result<String, String> {
    let mut canonical: Vec<String> = values.iter().map(|value| value.trim().to_string()).collect();
    canonical.sort();
    let json = serde_json::to_vec(&canonical).map_err(|_| "authorization proof metadata could not be canonicalized".to_string())?;
    Ok(sha256_hex(&json))
}

fn normal_payload_hash(payload: &BTreeMap<String, String>) -> String {
    let mut canonical = String::new();
    for (key, value) in payload {
        canonical.push_str(&format!("{}:{}={}:{}\n", key.len(), key, value.as_bytes().len(), value));
    }
    sha256_hex(canonical.as_bytes())
}

fn canonicalize_hostname(value: &str) -> Result<String, String> {
    let host = value.trim();
    if host.is_empty() || host.len() > 253 || !host.is_ascii() || host.ends_with('.')
        || host.contains("://") || host.contains('/') || host.contains('@') || host.contains(':')
        || host.contains('?') || host.contains('#') {
        return Err("authorization proof contains an invalid approved host".to_string());
    }
    let canonical = host.to_ascii_lowercase();
    for label in canonical.split('.') {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
            || !label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
            return Err("authorization proof contains an invalid approved host".to_string());
        }
    }
    Ok(canonical)
}

fn decode_claims(payload_part: &str) -> Result<AuthorizationClaims, String> {
    if payload_part.is_empty() || !payload_part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
        return Err("authorization proof payload is invalid".to_string());
    }
    let payload = URL_SAFE_NO_PAD.decode(payload_part.as_bytes())
        .map_err(|_| "authorization proof payload is invalid".to_string())?;
    serde_json::from_slice(&payload).map_err(|_| "authorization proof payload is invalid".to_string())
}

fn validate_time(claims: &AuthorizationClaims, now_ms: u64) -> Result<(), String> {
    if claims.issued_at == 0 || claims.expires_at <= claims.issued_at
        || claims.expires_at.saturating_sub(claims.issued_at) > MAX_CAPABILITY_LIFETIME_MS {
        return Err("authorization proof time bounds are invalid".to_string());
    }
    if claims.expires_at <= now_ms {
        return Err("authorization proof expired".to_string());
    }
    if claims.issued_at > now_ms.saturating_add(CLOCK_SKEW_MS) {
        return Err("authorization proof was issued in the future".to_string());
    }
    Ok(())
}

fn validate_bindings(claims: &AuthorizationClaims, request: &RemediationExecutionRequest) -> Result<(), String> {
    if !claims.executor_did.starts_with("did:t3n:") || claims.nonce.len() < 8 || claims.nonce.len() > 128
        || !claims.nonce.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte)) {
        return Err("authorization proof contains invalid provenance metadata".to_string());
    }
    if !is_sha256(&claims.fields_hash) || !is_sha256(&claims.normal_payload_hash)
        || !is_sha256(&claims.private_refs_hash) || !is_sha256(&claims.policy_hash) || claims.policy_version.trim().is_empty() {
        return Err("authorization proof contains invalid binding metadata".to_string());
    }
    let request_host = canonicalize_hostname(&request.approved_host)?;
    let claims_host = canonicalize_hostname(&claims.approved_host)?;
    let mismatched = claims.incident_id != request.incident_id
        || claims.action_id != request.action_id
        || claims.request_id != request.request_id
        || claims.decision_id != request.decision_id
        || claims.action != request.action
        || claims.resource != request.resource
        || claims.purpose != request.purpose
        || claims_host != request_host
        || claims.fields_hash != list_hash(&request.fields)?
        || claims.normal_payload_hash != normal_payload_hash(&request.normal_payload)
        || claims.private_refs_hash != list_hash(&request.private_refs)?
        || claims.policy_version != request.policy_version
        || claims.policy_hash != request.policy_hash
        || claims.executor_did != request.executor_did;
    if mismatched {
        return Err("authorization proof does not match the remediation request".to_string());
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn verify_proof(token: &str, request: &RemediationExecutionRequest, public_key_spki: &str, now_ms: u64) -> Result<AuthorizationClaims, String> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err("authorization proof is missing or exceeds the size limit".to_string());
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != TOKEN_VERSION {
        return Err("authorization proof version is unsupported".to_string());
    }
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2].as_bytes())
        .map_err(|_| "authorization proof signature is invalid".to_string())?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| "authorization proof signature is invalid".to_string())?;
    let public_der = STANDARD.decode(public_key_spki.trim().as_bytes())
        .map_err(|_| "authorization verification key is invalid".to_string())?;
    let public_key = VerifyingKey::from_public_key_der(&public_der)
        .map_err(|_| "authorization verification key is invalid".to_string())?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    public_key.verify(signing_input.as_bytes(), &signature)
        .map_err(|_| "authorization proof signature is invalid".to_string())?;

    let claims = decode_claims(parts[1])?;
    validate_time(&claims, now_ms)?;
    validate_bindings(&claims, request)?;
    Ok(claims)
}

#[cfg(target_arch = "wasm32")]
use crate::host::{interfaces::kv_store, tenant::tenant_context};

#[cfg(target_arch = "wasm32")]
fn now_millis() -> Result<u64, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| "trusted runtime clock is unavailable".to_string())?;
    u64::try_from(duration.as_millis()).map_err(|_| "trusted runtime clock is out of range".to_string())
}

#[cfg(target_arch = "wasm32")]
fn read_verification_key() -> Result<String, String> {
    let tid = tenant_context::tenant_did();
    let map_name = alloc::format!("z:{}:secrets", hex::encode(&tid));
    let bytes = kv_store::get(&map_name, b"remediation_auth_public_key_spki")
        .map_err(|_| "authorization verification key store is unavailable".to_string())?
        .ok_or_else(|| "authorization verification key is not provisioned".to_string())?;
    String::from_utf8(bytes).map_err(|_| "authorization verification key is invalid".to_string())
}

#[cfg(target_arch = "wasm32")]
fn consume_nonce(claims: &AuthorizationClaims, now_ms: u64) -> Result<(), String> {
    let tid = tenant_context::tenant_did();
    let map_name = alloc::format!("z:{}:privacy-guard-execution-nonces", hex::encode(&tid));
    let bucket_epoch = claims.expires_at / REPLAY_BUCKET_MS;
    let bucket_slot = bucket_epoch % REPLAY_BUCKET_SLOTS;
    let key = alloc::format!("slot-{bucket_slot}");
    let nonce_hash = sha256_hex(claims.nonce.as_bytes());

    let mut bucket = match kv_store::get(&map_name, key.as_bytes())
        .map_err(|_| "authorization replay store is unavailable".to_string())? {
        Some(bytes) => serde_json::from_slice::<ReplayBucket>(&bytes)
            .map_err(|_| "authorization replay store is invalid".to_string())?,
        None => ReplayBucket::default(),
    };
    if bucket.epoch != bucket_epoch {
        bucket = ReplayBucket { epoch: bucket_epoch, entries: Vec::new() };
    }
    bucket.entries.retain(|entry| entry.expires_at > now_ms);
    if bucket.entries.iter().any(|entry| entry.nonce_hash == nonce_hash) {
        return Err("authorization proof replay detected".to_string());
    }
    if bucket.entries.len() >= MAX_REPLAY_ENTRIES_PER_BUCKET {
        return Err("authorization replay bucket capacity exceeded".to_string());
    }
    bucket.entries.push(ReplayEntry { nonce_hash, expires_at: claims.expires_at });
    let encoded = serde_json::to_vec(&bucket).map_err(|_| "authorization replay state could not be encoded".to_string())?;
    kv_store::put(&map_name, key.as_bytes(), &encoded)
        .map_err(|_| "authorization replay state could not be persisted".to_string())?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn verify_and_consume(request: &RemediationExecutionRequest) -> Result<(), String> {
    let now_ms = now_millis()?;
    let public_key = read_verification_key()?;
    let claims = verify_proof(&request.authorization_proof, request, &public_key, now_ms)?;
    consume_nonce(&claims, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{pkcs8::DecodePrivateKey, Signer, SigningKey};

    const PRIVATE_KEY_PKCS8: &str = "MC4CAQAwBQYDK2VwBCIEIAv4OIfbF/R/i9uL6wgRalq2gperSKNx+Ig9BuS9L4qS";
    const PUBLIC_KEY_SPKI: &str = "MCowBQYDK2VwAyEAW3EwSatHmT/ZSgrqu/G3ecXJrTviA5SjAoCwIfwau6A=";
    const NOW: u64 = 1_800_000_000_000;

    fn request() -> RemediationExecutionRequest {
        RemediationExecutionRequest {
            incident_id: "incident-1".into(), action_id: "action-1".into(), decision_id: "decision-1".into(),
            request_id: "request-1".into(), agent_did: "did:t3n:proposal".into(), executor_did: "did:t3n:executor".into(),
            action: "revoke-credential".into(), resource: "credential:test".into(), purpose: "incident-remediation".into(),
            approved_host: "security-a.example".into(), fields: vec!["incident_id".into(), "credential_id".into(), "reason".into()],
            normal_payload: BTreeMap::from([
                ("credential_id".into(), "cred-demo-001".into()),
                ("incident_id".into(), "inc-demo-001".into()),
                ("reason".into(), "suspected compromise".into()),
            ]),
            private_refs: vec![], policy_version: "2026-09-12.1".into(), policy_hash: "a".repeat(64), authorization_proof: "placeholder".into(),
        }
    }

    fn signed_token(request: &RemediationExecutionRequest, nonce: &str) -> String {
        let claims = serde_json::json!({
            "incidentId": request.incident_id, "actionId": request.action_id, "requestId": request.request_id, "decisionId": request.decision_id,
            "action": request.action, "resource": request.resource, "purpose": request.purpose, "approvedHost": request.approved_host,
            "fieldsHash": list_hash(&request.fields).unwrap(), "normalPayloadHash": normal_payload_hash(&request.normal_payload),
            "privateRefsHash": list_hash(&request.private_refs).unwrap(), "policyVersion": request.policy_version,
            "policyHash": request.policy_hash, "executorDid": request.executor_did,
            "issuedAt": NOW - 1_000, "expiresAt": NOW + 60_000, "nonce": nonce
        });
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("v2.{payload}");
        let private_der = STANDARD.decode(PRIVATE_KEY_PKCS8).unwrap();
        let signing_key = SigningKey::from_pkcs8_der(&private_der).unwrap();
        let signature = signing_key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[test]
    fn valid_v2_proof_is_bound_to_the_entire_execution_request() {
        let mut request = request();
        request.authorization_proof = signed_token(&request, "nonce-00000001");
        assert!(verify_proof(&request.authorization_proof, &request, PUBLIC_KEY_SPKI, NOW).is_ok());
    }

    #[test]
    fn direct_execution_without_proof_and_legacy_v1_format_fail_closed() {
        let request = request();
        assert!(verify_proof("", &request, PUBLIC_KEY_SPKI, NOW).is_err());
        assert!(verify_proof("legacy.payload", &request, PUBLIC_KEY_SPKI, NOW).unwrap_err().contains("version"));
    }

    #[test]
    fn tampering_bound_payload_after_authorization_is_rejected() {
        let mut request = request();
        request.authorization_proof = signed_token(&request, "nonce-00000002");
        request.normal_payload.insert("reason".into(), "tampered".into());
        assert!(verify_proof(&request.authorization_proof, &request, PUBLIC_KEY_SPKI, NOW).unwrap_err().contains("does not match"));
    }

    #[test]
    fn expired_or_future_proof_is_rejected() {
        let claims = AuthorizationClaims {
            incident_id: "i".into(), action_id: "a".into(), request_id: "r".into(), decision_id: "d".into(),
            action: "x".into(), resource: "y".into(), purpose: "z".into(), approved_host: "security-a.example".into(),
            fields_hash: "a".repeat(64), normal_payload_hash: "b".repeat(64), private_refs_hash: "c".repeat(64),
            policy_version: "v".into(), policy_hash: "d".repeat(64), executor_did: "did:t3n:e".into(),
            issued_at: NOW - 61_000, expires_at: NOW - 1, nonce: "nonce-expired".into(),
        };
        assert!(validate_time(&claims, NOW).unwrap_err().contains("expired"));
        let future = AuthorizationClaims { issued_at: NOW + 6_000, expires_at: NOW + 66_000, ..claims };
        assert!(validate_time(&future, NOW).unwrap_err().contains("future"));
    }
}
