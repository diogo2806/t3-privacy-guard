use alloc::{format, string::{String, ToString}, vec::Vec};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_PROOF_BYTES: usize = 8_192;
const MAX_TTL_SECONDS: u64 = 300;
const CLOCK_SKEW_SECONDS: u64 = 5;
const NONCE_BUCKET_SECONDS: u64 = 10;
const NONCE_BUCKET_SLOTS: u64 = 64;
const MAX_NONCES_PER_BUCKET: usize = 512;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemediationAuthorizationClaims {
    pub key_id: String,
    pub incident_id: String,
    pub action_id: String,
    pub request_id: String,
    pub decision_id: String,
    pub action: String,
    pub resource: String,
    pub purpose: String,
    pub approved_host: String,
    pub fields_hash: String,
    pub private_refs_hash: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub executor_did: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
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
    pub private_refs: &'a [String],
    pub policy_version: &'a str,
    pub policy_hash: &'a str,
    pub executor_did: &'a str,
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(value: &[u8]) -> String {
    hex::encode(Sha256::digest(value))
}

fn list_hash(values: &[String]) -> Result<String, String> {
    let mut canonical: Vec<&str> = values.iter().map(|value| value.trim()).collect();
    canonical.sort_unstable();
    let bytes = serde_json::to_vec(&canonical).map_err(|_| "authorization proof metadata could not be canonicalized".to_string())?;
    Ok(sha256_hex(&bytes))
}

fn proof_parts(proof: &str) -> Result<(&str, &str), String> {
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
        return Err("AUTHORIZATION_PROOF_INVALID".to_string());
    }
    let mut parts = proof.split('.');
    let version = parts.next().ok_or("AUTHORIZATION_PROOF_INVALID")?;
    let payload = parts.next().ok_or("AUTHORIZATION_PROOF_INVALID")?;
    let signature = parts.next().ok_or("AUTHORIZATION_PROOF_INVALID")?;
    if parts.next().is_some() || version != "v2" || payload.is_empty() || !is_lower_hex(signature, 128) {
        return Err("AUTHORIZATION_PROOF_INVALID".to_string());
    }
    Ok((payload, signature))
}

fn decode_claims(payload: &str) -> Result<RemediationAuthorizationClaims, String> {
    let decoded = URL_SAFE_NO_PAD.decode(payload.as_bytes()).map_err(|_| "AUTHORIZATION_PROOF_INVALID".to_string())?;
    if decoded.len() > MAX_PROOF_BYTES {
        return Err("AUTHORIZATION_PROOF_INVALID".to_string());
    }
    serde_json::from_slice(&decoded).map_err(|_| "AUTHORIZATION_PROOF_INVALID".to_string())
}

pub fn key_id_from_proof(proof: &str) -> Result<String, String> {
    let (payload, _) = proof_parts(proof)?;
    let claims = decode_claims(payload)?;
    if !is_identifier(&claims.key_id) {
        return Err("AUTHORIZATION_PROOF_INVALID".to_string());
    }
    Ok(claims.key_id)
}

pub fn verify_proof(
    proof: &str,
    public_key_hex: &str,
    expected_key_id: &str,
    now: u64,
) -> Result<RemediationAuthorizationClaims, String> {
    if !is_identifier(expected_key_id) || !is_lower_hex(public_key_hex, 64) {
        return Err("AUTHORIZATION_VERIFICATION_KEY_INVALID".to_string());
    }
    let (payload, signature_hex) = proof_parts(proof)?;
    let claims = decode_claims(payload)?;
    if claims.key_id != expected_key_id || !is_identifier(&claims.key_id) {
        return Err("AUTHORIZATION_KEY_INACTIVE".to_string());
    }

    let public_key_bytes = hex::decode(public_key_hex).map_err(|_| "AUTHORIZATION_VERIFICATION_KEY_INVALID".to_string())?;
    let public_key_array: [u8; 32] = public_key_bytes.try_into().map_err(|_| "AUTHORIZATION_VERIFICATION_KEY_INVALID".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&public_key_array).map_err(|_| "AUTHORIZATION_VERIFICATION_KEY_INVALID".to_string())?;
    let signature_bytes = hex::decode(signature_hex).map_err(|_| "AUTHORIZATION_PROOF_INVALID".to_string())?;
    let signature_array: [u8; 64] = signature_bytes.try_into().map_err(|_| "AUTHORIZATION_PROOF_INVALID".to_string())?;
    let signature = Signature::from_bytes(&signature_array);
    let signing_input = format!("v2.{payload}");
    verifying_key.verify(signing_input.as_bytes(), &signature).map_err(|_| "AUTHORIZATION_SIGNATURE_INVALID".to_string())?;

    if claims.incident_id.trim().is_empty()
        || claims.action_id.trim().is_empty()
        || claims.request_id.trim().is_empty()
        || claims.decision_id.trim().is_empty()
        || claims.action.trim().is_empty()
        || claims.resource.trim().is_empty()
        || claims.purpose.trim().is_empty()
        || claims.approved_host.trim().is_empty()
        || claims.policy_version.trim().is_empty()
        || !is_lower_hex(&claims.fields_hash, 64)
        || !is_lower_hex(&claims.private_refs_hash, 64)
        || !is_lower_hex(&claims.policy_hash, 64)
        || !claims.executor_did.starts_with("did:t3n:")
        || !is_identifier(&claims.nonce)
    {
        return Err("AUTHORIZATION_PROOF_INVALID".to_string());
    }
    if claims.expires_at <= claims.issued_at || claims.expires_at - claims.issued_at > MAX_TTL_SECONDS {
        return Err("AUTHORIZATION_PROOF_INVALID".to_string());
    }
    if claims.issued_at > now.saturating_add(CLOCK_SKEW_SECONDS) {
        return Err("AUTHORIZATION_PROOF_INVALID".to_string());
    }
    if claims.expires_at <= now {
        return Err("AUTHORIZATION_PROOF_EXPIRED".to_string());
    }
    Ok(claims)
}

pub fn validate_binding(claims: &RemediationAuthorizationClaims, binding: &AuthorizationBinding<'_>) -> Result<(), String> {
    let mismatched = claims.incident_id != binding.incident_id
        || claims.action_id != binding.action_id
        || claims.request_id != binding.request_id
        || claims.decision_id != binding.decision_id
        || claims.action != binding.action
        || claims.resource != binding.resource
        || claims.purpose != binding.purpose
        || claims.approved_host != binding.approved_host
        || claims.fields_hash != list_hash(binding.fields)?
        || claims.private_refs_hash != list_hash(binding.private_refs)?
        || claims.policy_version != binding.policy_version
        || claims.policy_hash != binding.policy_hash
        || claims.executor_did != binding.executor_did;
    if mismatched {
        return Err("AUTHORIZATION_BODY_MISMATCH".to_string());
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
use crate::host::{interfaces::kv_store, tenant::tenant_context};

#[cfg(target_arch = "wasm32")]
fn authorization_map_name() -> String {
    let tid = tenant_context::tenant_did();
    format!("z:{}:privacy-guard-authorization", hex::encode(&tid))
}

#[cfg(target_arch = "wasm32")]
pub fn current_executor_did() -> Result<String, String> {
    let caller = tenant_context::calling_user_did().ok_or_else(|| "AUTHORIZATION_CALLER_UNAVAILABLE".to_string())?;
    Ok(format!("did:t3n:{}", hex::encode(caller)))
}

#[cfg(target_arch = "wasm32")]
pub fn load_active_verification_key(key_id: &str) -> Result<String, String> {
    if !is_identifier(key_id) {
        return Err("AUTHORIZATION_PROOF_INVALID".to_string());
    }
    let map_name = authorization_map_name();
    let active = kv_store::get(&map_name, b"active_key_id")
        .map_err(|_| "AUTHORIZATION_KEY_STORE_UNAVAILABLE".to_string())?
        .ok_or_else(|| "AUTHORIZATION_VERIFICATION_KEY_MISSING".to_string())?;
    let active = String::from_utf8(active).map_err(|_| "AUTHORIZATION_VERIFICATION_KEY_INVALID".to_string())?;
    if active != key_id {
        return Err("AUTHORIZATION_KEY_INACTIVE".to_string());
    }
    let key_name = format!("verification_key:{key_id}");
    let key = kv_store::get(&map_name, key_name.as_bytes())
        .map_err(|_| "AUTHORIZATION_KEY_STORE_UNAVAILABLE".to_string())?
        .ok_or_else(|| "AUTHORIZATION_VERIFICATION_KEY_MISSING".to_string())?;
    let key = String::from_utf8(key).map_err(|_| "AUTHORIZATION_VERIFICATION_KEY_INVALID".to_string())?;
    if !is_lower_hex(&key, 64) {
        return Err("AUTHORIZATION_VERIFICATION_KEY_INVALID".to_string());
    }
    Ok(key)
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Deserialize, Serialize)]
struct ReplayBucket {
    epoch: u64,
    retain_until: u64,
    nonce_hashes: Vec<String>,
}

#[cfg(target_arch = "wasm32")]
pub fn consume_nonce(claims: &RemediationAuthorizationClaims, now: u64) -> Result<(), String> {
    let map_name = authorization_map_name();
    let epoch = claims.issued_at / NONCE_BUCKET_SECONDS;
    let slot = epoch % NONCE_BUCKET_SLOTS;
    let key = format!("nonce-bucket:{slot}");
    let nonce_hash = sha256_hex(claims.nonce.as_bytes());
    let existing = kv_store::get(&map_name, key.as_bytes())
        .map_err(|_| "AUTHORIZATION_REPLAY_STORE_UNAVAILABLE".to_string())?;
    let mut bucket = match existing {
        Some(bytes) => serde_json::from_slice::<ReplayBucket>(&bytes)
            .map_err(|_| "AUTHORIZATION_REPLAY_STORE_UNAVAILABLE".to_string())?,
        None => ReplayBucket { epoch, retain_until: claims.expires_at.saturating_add(CLOCK_SKEW_SECONDS), nonce_hashes: Vec::new() },
    };

    if bucket.epoch != epoch {
        if now <= bucket.retain_until {
            return Err("AUTHORIZATION_REPLAY_STORE_BUSY".to_string());
        }
        bucket = ReplayBucket { epoch, retain_until: claims.expires_at.saturating_add(CLOCK_SKEW_SECONDS), nonce_hashes: Vec::new() };
    }
    if bucket.nonce_hashes.iter().any(|value| value == &nonce_hash) {
        return Err("AUTHORIZATION_REPLAY".to_string());
    }
    if bucket.nonce_hashes.len() >= MAX_NONCES_PER_BUCKET {
        return Err("AUTHORIZATION_REPLAY_STORE_FULL".to_string());
    }
    bucket.retain_until = bucket.retain_until.max(claims.expires_at.saturating_add(CLOCK_SKEW_SECONDS));
    bucket.nonce_hashes.push(nonce_hash);
    let value = serde_json::to_vec(&bucket).map_err(|_| "AUTHORIZATION_REPLAY_STORE_UNAVAILABLE".to_string())?;
    kv_store::put(&map_name, key.as_bytes(), &value)
        .map_err(|_| "AUTHORIZATION_REPLAY_STORE_UNAVAILABLE".to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const NOW: u64 = 1_800_000_000;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ])
    }

    fn claims() -> RemediationAuthorizationClaims {
        RemediationAuthorizationClaims {
            key_id: "primary-v2".into(),
            incident_id: "incident-1".into(),
            action_id: "action-1".into(),
            request_id: "request-1".into(),
            decision_id: "decision-1".into(),
            action: "revoke-credential".into(),
            resource: "credential:test".into(),
            purpose: "incident-remediation".into(),
            approved_host: "security.example".into(),
            fields_hash: list_hash(&["credential_id".into(), "incident_id".into()]).unwrap(),
            private_refs_hash: list_hash(&[]).unwrap(),
            policy_version: "2026-09-13.1".into(),
            policy_hash: "a".repeat(64),
            executor_did: "did:t3n:executor".into(),
            issued_at: NOW - 1,
            expires_at: NOW + 60,
            nonce: "nonce-1234567890".into(),
        }
    }

    fn proof(input: &RemediationAuthorizationClaims) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(input).unwrap());
        let signing_input = format!("v2.{payload}");
        let signature = signing_key().sign(signing_input.as_bytes());
        format!("{signing_input}.{}", hex::encode(signature.to_bytes()))
    }

    fn public_key_hex() -> String {
        hex::encode(signing_key().verifying_key().to_bytes())
    }

    #[test]
    fn valid_v2_proof_verifies_and_binds_exact_request() {
        let claims = claims();
        let token = proof(&claims);
        let verified = verify_proof(&token, &public_key_hex(), "primary-v2", NOW).unwrap();
        let fields = vec!["incident_id".into(), "credential_id".into()];
        let private_refs = vec![];
        let binding = AuthorizationBinding {
            incident_id: "incident-1", action_id: "action-1", request_id: "request-1", decision_id: "decision-1",
            action: "revoke-credential", resource: "credential:test", purpose: "incident-remediation", approved_host: "security.example",
            fields: &fields, private_refs: &private_refs, policy_version: "2026-09-13.1", policy_hash: &"a".repeat(64), executor_did: "did:t3n:executor",
        };
        assert!(validate_binding(&verified, &binding).is_ok());
    }

    #[test]
    fn altered_signature_expired_future_and_legacy_proofs_fail_closed() {
        let valid = proof(&claims());
        let mut tampered = valid.clone().into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
        assert_eq!(verify_proof(&String::from_utf8(tampered).unwrap(), &public_key_hex(), "primary-v2", NOW).unwrap_err(), "AUTHORIZATION_SIGNATURE_INVALID");

        let mut expired = claims();
        expired.issued_at = NOW - 61;
        expired.expires_at = NOW;
        assert_eq!(verify_proof(&proof(&expired), &public_key_hex(), "primary-v2", NOW).unwrap_err(), "AUTHORIZATION_PROOF_EXPIRED");

        let mut future = claims();
        future.issued_at = NOW + 6;
        future.expires_at = NOW + 60;
        assert_eq!(verify_proof(&proof(&future), &public_key_hex(), "primary-v2", NOW).unwrap_err(), "AUTHORIZATION_PROOF_INVALID");
        assert_eq!(key_id_from_proof("v1.payload.signature").unwrap_err(), "AUTHORIZATION_PROOF_INVALID");
    }

    #[test]
    fn every_security_relevant_binding_is_fail_closed() {
        let verified = verify_proof(&proof(&claims()), &public_key_hex(), "primary-v2", NOW).unwrap();
        let fields = vec!["incident_id".into(), "credential_id".into()];
        let private_refs = vec![];
        let policy_hash = "a".repeat(64);
        let base = AuthorizationBinding {
            incident_id: "incident-1", action_id: "action-1", request_id: "request-1", decision_id: "decision-1",
            action: "revoke-credential", resource: "credential:test", purpose: "incident-remediation", approved_host: "security.example",
            fields: &fields, private_refs: &private_refs, policy_version: "2026-09-13.1", policy_hash: &policy_hash, executor_did: "did:t3n:executor",
        };
        assert!(validate_binding(&verified, &AuthorizationBinding { incident_id: "other", ..base }).is_err());
        let base = AuthorizationBinding { incident_id: "incident-1", ..base };
        assert!(validate_binding(&verified, &AuthorizationBinding { action_id: "other", ..base }).is_err());
        let base = AuthorizationBinding { action_id: "action-1", ..base };
        assert!(validate_binding(&verified, &AuthorizationBinding { request_id: "other", ..base }).is_err());
        let base = AuthorizationBinding { request_id: "request-1", ..base };
        assert!(validate_binding(&verified, &AuthorizationBinding { decision_id: "other", ..base }).is_err());
        let base = AuthorizationBinding { decision_id: "decision-1", ..base };
        assert!(validate_binding(&verified, &AuthorizationBinding { approved_host: "other.example", ..base }).is_err());
        let base = AuthorizationBinding { approved_host: "security.example", ..base };
        assert!(validate_binding(&verified, &AuthorizationBinding { executor_did: "did:t3n:other", ..base }).is_err());
    }
}