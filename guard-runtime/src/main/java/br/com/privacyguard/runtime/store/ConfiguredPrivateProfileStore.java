package br.com.privacyguard.runtime.store;

import java.util.Optional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Single-tenant profile from configuration; the only private value the contract maps is the verified email. */
@Component
public class ConfiguredPrivateProfileStore implements PrivateProfileStore {
    static final String VERIFIED_EMAIL_PATH = "profile.verified_contacts.email.value";

    private final String verifiedEmail;

    public ConfiguredPrivateProfileStore(@Value("${guard-runtime.profile.verified-email:}") String verifiedEmail) {
        this.verifiedEmail = verifiedEmail == null || verifiedEmail.isBlank() ? null : verifiedEmail.trim();
    }

    @Override
    public Optional<String> resolve(String path) {
        return VERIFIED_EMAIL_PATH.equals(path) ? Optional.ofNullable(verifiedEmail) : Optional.empty();
    }
}
