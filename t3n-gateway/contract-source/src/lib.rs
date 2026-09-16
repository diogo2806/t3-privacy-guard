#![warn(clippy::style)]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

pub const CONTRACT_VERSION: &str = "0.4.0";

wit_bindgen::generate!({
    world: "privacy-guard",
    path: "wit",
    additional_derives: [serde::Deserialize, serde::Serialize],
    generate_all,
});

pub mod authorization;
pub mod policy;
pub mod remediation;

struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::privacy_guard::contracts::Guest for Component {
    fn evaluate_action(req: exports::z::privacy_guard::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("evaluate-action: missing input")?;
        policy::evaluate_json(&input)
    }

    fn execute_remediation(req: exports::z::privacy_guard::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("execute-remediation: missing input")?;
        remediation::execute_remediation(&input)
    }

    fn verify_remediation(req: exports::z::privacy_guard::contracts::GenericInput) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("verify-remediation: missing input")?;
        remediation::verify_remediation(&input)
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

#[cfg(test)]
mod tests {
    use super::CONTRACT_VERSION;
    #[test]
    fn contract_version_is_semver() {
        let parts: Vec<&str> = CONTRACT_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|part| part.parse::<u32>().is_ok()));
    }
}
