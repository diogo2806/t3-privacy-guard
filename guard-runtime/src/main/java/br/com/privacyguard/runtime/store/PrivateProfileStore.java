package br.com.privacyguard.runtime.store;

import java.util.Optional;

/**
 * Replaces the T3N user profile behind {{profile.*}} placeholders. Only the egress layer reads it, at the moment
 * of the outbound call; contract logic, gateway, backend and model only ever see the logical reference.
 */
public interface PrivateProfileStore {
    /** path is the placeholder body without braces, e.g. "profile.verified_contacts.email.value". */
    Optional<String> resolve(String path);
}
