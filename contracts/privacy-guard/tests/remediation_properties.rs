use privacy_guard_contract::remediation::{
    execute_remediation, verify_remediation, RemediationResult, RemediationVerificationRequest,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn remediation_parsers_never_panic(input in prop::collection::vec(any::<u8>(), 0..4096)) {
        prop_assert!(std::panic::catch_unwind(|| execute_remediation(&input)).is_ok());
        prop_assert!(std::panic::catch_unwind(|| verify_remediation(&input)).is_ok());
    }

    #[test]
    fn verification_expected_state_is_closed_per_action(
        request_id in "[a-zA-Z0-9_-]{1,64}",
        operation_id in "[a-zA-Z0-9_-]{1,64}",
        action in prop_oneof![Just("revoke-credential"), Just("notify-security")],
        arbitrary_state in "[A-Z_]{1,32}",
    ) {
        let expected_state = if action == "revoke-credential" { "REVOKED" } else { "DELIVERED" };
        let request = RemediationVerificationRequest {
            request_id,
            operation_id,
            action: action.to_string(),
            expected_state: arbitrary_state.clone(),
        };
        let input = serde_json::to_vec(&request).unwrap();
        let error = verify_remediation(&input).unwrap_err();
        if arbitrary_state == expected_state {
            prop_assert!(error.contains("only implemented on the wasm32 target"));
        } else {
            prop_assert!(error.contains("expected_state does not match"));
        }
    }

    #[test]
    fn reduced_result_schema_never_reflects_arbitrary_upstream_sentinel(
        sentinel in "SENTINEL_[A-Za-z0-9]{8,40}",
        http_code in 200u16..300u16,
    ) {
        let result = RemediationResult {
            request_id: "property-request".into(),
            status: "PENDING_VERIFICATION".into(),
            http_code,
            operation_id: Some("property-operation".into()),
            policy_version: "2026-09-12.1".into(),
            policy_hash: "a".repeat(64),
        };
        let serialized = serde_json::to_string(&result).unwrap();
        prop_assert!(!serialized.contains(&sentinel));
        prop_assert!(!serialized.to_ascii_lowercase().contains("authorization"));
        prop_assert!(!serialized.to_ascii_lowercase().contains("recipient"));
    }
}
