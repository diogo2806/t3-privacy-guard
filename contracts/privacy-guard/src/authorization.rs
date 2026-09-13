use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const TOKEN_VERSION: &str = "v2";
const MAX_PROOF_BYTES: usize = 8192;
const MAX_PAYLOAD_BYTES: usize = 4096;
const MAX_TTL_MS: u64 = 300_000;
const MIN_TTL_MS: u64 = 10_000;
const CLOCK_SKEW_MS: u64 = 5_000;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthorizationClaims {
    key_id: String,
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
    operator_principal_hash: String,
    authorized_at: u64,
    issued_at: u64,
    expires_at: u64,
    nonce: String,
}

pub struct AuthorizationBinding<'a> {
    pub incident_id: &'a str,
    pub action_id: &'a str,
    pub request_id: &'a str,
    pub decision_id: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    pub purpose: &'a str,
    pub approved_host: &'a str,
    pub fields: &'a [String],
    pub normal_payload: &'a BTreeMap<String, String>,
    pub private_refs: &'a [String],
    pub policy_version: &'a str,
    pub policy_hash: &'a str,
    pub executor_did: &'a str,
    pub operator_principal_hash: &'a str,
    pub authorization_recorded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuthorization {
    pub nonce: String,
    pub expires_at: u64,
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn list_hash(values: &[String]) -> Result<String, String> {
    let mut canonical: Vec<String> = values.iter().map(|value| value.trim().to_string()).collect();
    canonical.sort();
    let json = serde_json::to_vec(&canonical).map_err(|_| "CAPABILITY_INVALID".to_string())?;
    Ok(sha256_hex(&json))
}

fn normal_payload_hash(payload: &BTreeMap<String, String>) -> Result<String, String> {
    if payload.len() > 16 {
        return Err("CAPABILITY_INVALID".to_string());
    }
    let mut canonical = String::new();
    for (key, value) in payload {
        if key.is_empty() || key.len() > 80 || !key.as_bytes()[0].is_ascii_lowercase()
            || !key.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || value.trim().is_empty() || value.as_bytes().len() > 512 {
            return Err("CAPABILITY_INVALID".to_string());
        }
        canonical.push_str(&format!("{}:{}={}:{}\n", key.len(), key, value.as_bytes().len(), value));
    }
    Ok(sha256_hex(canonical.as_bytes()))
}

fn decode_public_key(encoded: &str) -> Result<VerifyingKey, String> {
    let raw = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| "CAPABILITY_PUBLIC_KEY_INVALID".to_string())?;
    let bytes: [u8; 32] = raw.try_into().map_err(|_| "CAPABILITY_PUBLIC_KEY_INVALID".to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| "CAPABILITY_PUBLIC_KEY_INVALID".to_string())
}

fn verify_signature(payload_part: &str, signature_part: &str, public_key: &VerifyingKey) -> Result<(), String> {
    let raw = URL_SAFE_NO_PAD.decode(signature_part).map_err(|_| "CAPABILITY_INVALID".to_string())?;
    let signature = Signature::from_slice(&raw).map_err(|_| "CAPABILITY_INVALID".to_string())?;
    public_key.verify_strict(payload_part.as_bytes(), &signature).map_err(|_| "CAPABILITY_INVALID".to_string())
}

pub fn verify_authorization_proof(
    proof: &str,
    expected_key_id: &str,
    public_key_b64url: &str,
    binding: &AuthorizationBinding<'_>,
    now_ms: u64,
) -> Result<VerifiedAuthorization, String> {
    if proof.is_empty() {
        return Err("CAPABILITY_REQUIRED".to_string());
    }
    if proof.as_bytes().len() > MAX_PROOF_BYTES {
        return Err("CAPABILITY_INVALID".to_string());
    }
    let mut parts = proof.split('.');
    let version = parts.next().ok_or("CAPABILITY_INVALID")?;
    let payload_part = parts.next().ok_or("CAPABILITY_INVALID")?;
    let signature_part = parts.next().ok_or("CAPABILITY_INVALID")?;
    if parts.next().is_some() || version != TOKEN_VERSION || payload_part.is_empty() || signature_part.is_empty() {
        return Err("CAPABILITY_INVALID".to_string());
    }

    let public_key = decode_public_key(public_key_b64url)?;
    verify_signature(payload_part, signature_part, &public_key)?;
    let payload = URL_SAFE_NO_PAD.decode(payload_part).map_err(|_| "CAPABILITY_INVALID".to_string())?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err("CAPABILITY_INVALID".to_string());
    }
    let claims: AuthorizationClaims = serde_json::from_slice(&payload).map_err(|_| "CAPABILITY_INVALID".to_string())?;

    if claims.key_id != expected_key_id || claims.nonce.is_empty() || claims.nonce.len() > 128 {
        return Err("CAPABILITY_KEY_MISMATCH".to_string());
    }
    if claims.expires_at <= now_ms {
        return Err("CAPABILITY_EXPIRED".to_string());
    }
    if claims.authorized_at == 0 || claims.issued_at == 0 || claims.authorized_at > claims.issued_at
        || claims.issued_at > now_ms.saturating_add(CLOCK_SKEW_MS)
        || claims.expires_at <= claims.issued_at
        || claims.expires_at.saturating_sub(claims.issued_at) < MIN_TTL_MS
        || claims.expires_at.saturating_sub(claims.issued_at) > MAX_TTL_MS
        || !is_hex_64(&claims.policy_hash)
        || !is_hex_64(&claims.normal_payload_hash)
        || !is_hex_64(&claims.operator_principal_hash)
        || !claims.executor_did.starts_with("did:t3n:") {
        return Err("CAPABILITY_INVALID".to_string());
    }

    let mismatched = claims.incident_id != binding.incident_id
        || claims.action_id != binding.action_id
        || claims.request_id != binding.request_id
        || claims.decision_id != binding.decision_id
        || claims.action != binding.action
        || claims.resource != binding.resource
        || claims.purpose != binding.purpose
        || claims.approved_host != binding.approved_host
        || claims.fields_hash != list_hash(binding.fields)?
        || claims.normal_payload_hash != normal_payload_hash(binding.normal_payload)?
        || claims.private_refs_hash != list_hash(binding.private_refs)?
        || claims.policy_version != binding.policy_version
        || claims.policy_hash != binding.policy_hash
        || claims.executor_did != binding.executor_did
        || claims.operator_principal_hash != binding.operator_principal_hash
        || claims.authorized_at != binding.authorization_recorded_at;
    if mismatched {
        return Err("CAPABILITY_BODY_MISMATCH".to_string());
    }

    Ok(VerifiedAuthorization { nonce: claims.nonce, expires_at: claims.expires_at })
}

#[cfg(target_arch = "wasm32")]
use crate::host::{interfaces::kv_store, tenant::tenant_context};

#[cfg(target_arch = "wasm32")]
fn authorization_map_name() -> String {
    let tid = tenant_context::tenant_did();
    alloc::format!("z:{}:remediation-authorization", hex::encode(&tid))
}

#[cfg(target_arch = "wasm32")]
fn read_authorization_entry(map_name: &str, key: &str) -> Result<String, String> {
    let bytes = kv_store::get(map_name, key.as_bytes())
        .map_err(|_| "CAPABILITY_STORE_UNAVAILABLE".to_string())?
        .ok_or_else(|| "CAPABILITY_KEY_UNAVAILABLE".to_string())?;
    String::from_utf8(bytes).map_err(|_| "CAPABILITY_KEY_UNAVAILABLE".to_string())
}

#[cfg(target_arch = "wasm32")]
fn current_time_ms() -> Result<u64, String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "CAPABILITY_CLOCK_UNAVAILABLE".to_string())?;
    u64::try_from(duration.as_millis()).map_err(|_| "CAPABILITY_CLOCK_UNAVAILABLE".to_string())
}

#[cfg(target_arch = "wasm32")]
pub fn verify_and_consume_authorization(proof: &str, binding: &AuthorizationBinding<'_>) -> Result<(), String> {
    let map_name = authorization_map_name();
    let active_key_id = read_authorization_entry(&map_name, "active_key_id")?;
    let public_key = read_authorization_entry(&map_name, &alloc::format!("verification_key:{active_key_id}"))?;
    let verified = verify_authorization_proof(proof, &active_key_id, &public_key, binding, current_time_ms()?)?;
    let nonce_hash = sha256_hex(verified.nonce.as_bytes());
    let nonce_key = alloc::format!("nonce:{nonce_hash}");
    if kv_store::get(&map_name, nonce_key.as_bytes())
        .map_err(|_| "CAPABILITY_STORE_UNAVAILABLE".to_string())?
        .is_some() {
        return Err("CAPABILITY_REPLAY".to_string());
    }
    kv_store::put(&map_name, nonce_key.as_bytes(), verified.expires_at.to_string().as_bytes())
        .map_err(|_| "CAPABILITY_STORE_UNAVAILABLE".to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const PUBLIC_KEY: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];

    fn normal_payload() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("credential_id".into(), "cred-demo-001".into()),
            ("incident_id".into(), "inc-demo-001".into()),
            ("reason".into(), "suspected compromise".into()),
        ])
    }

    fn binding<'a>(fields: &'a [String], payload: &'a BTreeMap<String, String>, refs: &'a [String]) -> AuthorizationBinding<'a> {
        AuthorizationBinding {
            incident_id: "incident-1", action_id: "action-1", request_id: "request-1", decision_id: "decision-1",
            action: "revoke-credential", resource: "credential:test", purpose: "incident-remediation", approved_host: "security-a.example",
            fields, normal_payload: payload, private_refs: refs, policy_version: "2026-09-12.1", policy_hash: "a".repeat(64).leak(),
            executor_did: "did:t3n:protected-executor-test", operator_principal_hash: "b".repeat(64).leak(), authorization_recorded_at: 1_799_999_998_000,
        }
    }

    fn token(fields: &[String], payload: &BTreeMap<String, String>, refs: &[String], expires_at: u64, purpose: &str) -> String {
        let claims = AuthorizationClaims {
            key_id: "v1".into(), incident_id: "incident-1".into(), action_id: "action-1".into(), request_id: "request-1".into(), decision_id: "decision-1".into(),
            action: "revoke-credential".into(), resource: "credential:test".into(), purpose: purpose.into(), approved_host: "security-a.example".into(),
            fields_hash: list_hash(fields).unwrap(), normal_payload_hash: normal_payload_hash(payload).unwrap(), private_refs_hash: list_hash(refs).unwrap(),
            policy_version: "2026-09-12.1".into(), policy_hash: "a".repeat(64), executor_did: "did:t3n:protected-executor-test".into(),
            operator_principal_hash: "b".repeat(64), authorized_at: 1_799_999_998_000, issued_at: 1_799_999_999_000, expires_at, nonce: "nonce-1".into(),
        };
        let payload_bytes = serde_json::to_vec(&claims).unwrap();
        let payload_part = URL_SAFE_NO_PAD.encode(payload_bytes);
        let signing_key = SigningKey::from_bytes(&SEED);
        let signature = signing_key.sign(payload_part.as_bytes());
        format!("v2.{payload_part}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    #[test]
    fn valid_signed_proof_matches_all_execution_bindings() {
        let fields = vec!["incident_id".into(), "credential_id".into(), "reason".into()];
        let payload = normal_payload();
        let refs = vec![];
        let proof = token(&fields, &payload, &refs, 1_800_000_060_000, "incident-remediation");
        let verified = verify_authorization_proof(&proof, "v1", PUBLIC_KEY, &binding(&fields, &payload, &refs), 1_800_000_000_000).unwrap();
        assert_eq!(verified.nonce, "nonce-1");
    }

    #[test]
    fn missing_tampered_expired_or_body_mismatched_proof_fails_closed() {
        let fields = vec!["incident_id".into(), "credential_id".into(), "reason".into()];
        let payload = normal_payload();
        let refs = vec![];
        let valid = token(&fields, &payload, &refs, 1_800_000_060_000, "incident-remediation");
        assert_eq!(verify_authorization_proof("", "v1", PUBLIC_KEY, &binding(&fields, &payload, &refs), 1_800_000_000_000).unwrap_err(), "CAPABILITY_REQUIRED");
        let mut tampered = valid.clone().into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(verify_authorization_proof(std::str::from_utf8(&tampered).unwrap(), "v1", PUBLIC_KEY, &binding(&fields, &payload, &refs), 1_800_000_000_000).unwrap_err(), "CAPABILITY_INVALID");
        let expired = token(&fields, &payload, &refs, 1_799_999_999_999, "incident-remediation");
        assert_eq!(verify_authorization_proof(&expired, "v1", PUBLIC_KEY, &binding(&fields, &payload, &refs), 1_800_000_000_000).unwrap_err(), "CAPABILITY_EXPIRED");
        let wrong_body = token(&fields, &payload, &refs, 1_800_000_060_000, "analytics");
        assert_eq!(verify_authorization_proof(&wrong_body, "v1", PUBLIC_KEY, &binding(&fields, &payload, &refs), 1_800_000_000_000).unwrap_err(), "CAPABILITY_BODY_MISMATCH");
    }
}
