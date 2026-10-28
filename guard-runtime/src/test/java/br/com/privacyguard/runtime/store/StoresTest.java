package br.com.privacyguard.runtime.store;

import static br.com.privacyguard.runtime.testing.CapabilityTokens.NOW;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.PUBLIC_KEY_SPKI;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.revokeRequest;
import static br.com.privacyguard.runtime.testing.CapabilityTokens.signedToken;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.privacyguard.runtime.authorization.AuthorizationClaims;
import br.com.privacyguard.runtime.authorization.CapabilityVerifier;
import br.com.privacyguard.runtime.contract.ContractRejectedException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class StoresTest {
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC);

    @TempDir
    Path temp;

    private static AuthorizationClaims claims(String nonce) {
        return CapabilityVerifier.verify(signedToken(revokeRequest("agent:executor"), nonce), revokeRequest("agent:executor"), PUBLIC_KEY_SPKI, NOW);
    }

    @Test
    void consumedNoncesSurviveARestart() {
        Path file = temp.resolve("nested/replay.json");
        new FileReplayStore(file.toString(), new ObjectMapper()).consume(claims("nonce-store-0001"), NOW);
        FileReplayStore restarted = new FileReplayStore(file.toString(), new ObjectMapper());
        assertThatThrownBy(() -> restarted.consume(claims("nonce-store-0001"), NOW)).isInstanceOf(ContractRejectedException.class).hasMessageContaining("replay");
        restarted.consume(claims("nonce-store-0002"), NOW);
    }

    @Test
    void corruptReplayStateFailsClosed() throws Exception {
        Path file = temp.resolve("replay.json");
        Files.writeString(file, "not-json");
        assertThatThrownBy(() -> new FileReplayStore(file.toString(), new ObjectMapper()).consume(claims("nonce-store-0003"), NOW))
            .isInstanceOf(ContractRejectedException.class).hasMessage("authorization replay store is invalid");
    }

    @Test
    void privateConfigurationMapsEnvironmentToTheContractKeys() {
        String pem = "-----BEGIN PUBLIC KEY-----\n" + PUBLIC_KEY_SPKI + "\n-----END PUBLIC KEY-----\n";
        EnvironmentPrivateConfigStore store = new EnvironmentPrivateConfigStore(
            "https://security-a.example/execute", "https://security-a.example/verify", "api-key-value-0123456789",
            "primary", Base64.getEncoder().encodeToString(pem.getBytes()), "previous", PUBLIC_KEY_SPKI, "120", CLOCK);
        assertThat(store.get("security_api_url")).contains("https://security-a.example/execute");
        assertThat(store.get("remediation_auth_active_key_id")).contains("primary");
        assertThat(store.get("remediation_auth_public_key_spki:primary")).contains(PUBLIC_KEY_SPKI);
        assertThat(store.get("remediation_auth_key_valid_until:previous")).contains(Long.toString(NOW + 120_000));
    }

    @Test
    void withoutAVerificationKeyNothingCanBeAuthorized() {
        EnvironmentPrivateConfigStore store = new EnvironmentPrivateConfigStore("", "", "", "primary", "", "", "", "", CLOCK);
        assertThat(store.get("remediation_auth_active_key_id")).isEmpty();
        assertThat(store.get("security_api_key")).isEmpty();
    }

    @Test
    void invalidPrivateConfigurationIsRejectedAtStartup() {
        assertThatThrownBy(() -> new EnvironmentPrivateConfigStore("", "", "replace-with-real-key", "primary", "", "", "", "", CLOCK))
            .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new EnvironmentPrivateConfigStore("", "", "", "primary", "not-a-key", "", "", "", CLOCK))
            .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new EnvironmentPrivateConfigStore("", "", "", "primary", PUBLIC_KEY_SPKI, "previous", "", "60", CLOCK))
            .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new EnvironmentPrivateConfigStore("", "", "", "primary", PUBLIC_KEY_SPKI, "previous", PUBLIC_KEY_SPKI, "301", CLOCK))
            .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void profileResolvesOnlyTheVerifiedEmailPath() {
        ConfiguredPrivateProfileStore profile = new ConfiguredPrivateProfileStore(" soc@example.test ");
        assertThat(profile.resolve("profile.verified_contacts.email.value")).contains("soc@example.test");
        assertThat(profile.resolve("profile.home_address")).isEmpty();
        assertThat(new ConfiguredPrivateProfileStore("").resolve("profile.verified_contacts.email.value")).isEmpty();
    }
}
