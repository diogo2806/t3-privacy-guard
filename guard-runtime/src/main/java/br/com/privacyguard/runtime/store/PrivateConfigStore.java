package br.com.privacyguard.runtime.store;

import java.util.Optional;

/**
 * Replaces the private T3N KV map "secrets". Keys keep the contract's names: security_api_url,
 * security_verification_url, security_api_key, remediation_auth_active_key_id,
 * remediation_auth_public_key_spki:&lt;key id&gt; and remediation_auth_key_valid_until:&lt;key id&gt;.
 */
public interface PrivateConfigStore {
    Optional<String> get(String key);
}
