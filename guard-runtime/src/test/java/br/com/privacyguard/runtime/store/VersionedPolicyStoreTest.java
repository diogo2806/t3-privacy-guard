package br.com.privacyguard.runtime.store;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.privacyguard.runtime.policy.PolicyDocumentParser;
import br.com.privacyguard.runtime.store.ManagedPolicyStore.Change;
import br.com.privacyguard.runtime.store.ManagedPolicyStore.PolicyChangeException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class VersionedPolicyStoreTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-10-28T12:00:00Z"), ZoneOffset.UTC);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @TempDir
    Path temp;

    @Test
    void seedFileBecomesTheFirstVersionAndSurvivesARestart() throws IOException {
        Path seed = writeSeed(policy("v1", "incident_id"));
        VersionedPolicyStore store = store(seed);

        assertThat(store.currentPolicy()).get().extracting(policy -> policy.version()).isEqualTo("v1");
        assertThat(store.history()).singleElement().satisfies(entry -> {
            assertThat(entry.operation()).isEqualTo("seed");
            assertThat(entry.caller()).isEqualTo(VersionedPolicyStore.SEED_CALLER);
        });

        VersionedPolicyStore restarted = store(seed);
        assertThat(restarted.history()).hasSize(1);
        assertThat(restarted.current()).get().isEqualTo(store.current().orElseThrow());
    }

    @Test
    void publishRequiresTheCurrentHashAndANewVersion() {
        VersionedPolicyStore store = store(writeSeed(policy("v1", "incident_id")));
        String v1 = store.currentPolicy().orElseThrow().hash();

        assertThatThrownBy(() -> store.publish(policy("v2", "incident_id"), "0".repeat(64), "agent:admin", "alice"))
            .isInstanceOfSatisfying(PolicyChangeException.class, ex -> assertThat(ex.code()).isEqualTo(PolicyChangeException.POLICY_CHANGED));

        Change published = store.publish(policy("v2", "incident_id", "reason"), v1, "agent:admin", "alice");
        assertThat(published.changed()).isTrue();
        assertThat(published.previousVersion()).isEqualTo("v1");
        assertThat(store.currentPolicy().orElseThrow().version()).isEqualTo("v2");

        assertThatThrownBy(() -> store.publish(policy("v1", "incident_id", "reason"), published.hash(), "agent:admin", "alice"))
            .isInstanceOfSatisfying(PolicyChangeException.class, ex -> assertThat(ex.code()).isEqualTo(PolicyChangeException.VERSION_EXISTS));
    }

    @Test
    void republishingTheCurrentDocumentIsANoOp() {
        VersionedPolicyStore store = store(writeSeed(policy("v1", "incident_id")));
        String v1 = store.currentPolicy().orElseThrow().hash();

        Change change = store.publish(policy("v1", "incident_id"), v1, "agent:admin", "alice");

        assertThat(change.changed()).isFalse();
        assertThat(store.history()).hasSize(1);
    }

    @Test
    void invalidDocumentsKeepTheContractRules() {
        VersionedPolicyStore store = store(writeSeed(policy("v1", "incident_id")));
        String v1 = store.currentPolicy().orElseThrow().hash();

        assertThatThrownBy(() -> store.publish(policy("v2", "api_key"), v1, "agent:admin", "alice"))
            .isInstanceOfSatisfying(PolicyChangeException.class, ex -> {
                assertThat(ex.code()).isEqualTo(PolicyChangeException.POLICY_INVALID);
                assertThat(ex.getMessage()).contains("forbidden secret field");
            });
        assertThat(store.currentPolicy().orElseThrow().version()).isEqualTo("v1");
    }

    @Test
    void rollbackRestoresAnEarlierVersionAndIsRecorded() {
        VersionedPolicyStore store = store(writeSeed(policy("v1", "incident_id")));
        String v1 = store.currentPolicy().orElseThrow().hash();
        Change v2 = store.publish(policy("v2", "incident_id", "reason"), v1, "agent:admin", "alice");

        Change rolledBack = store.rollback("v1", v2.hash(), "agent:admin", "bob");

        assertThat(rolledBack.changed()).isTrue();
        assertThat(rolledBack.hash()).isEqualTo(v1);
        assertThat(store.history()).extracting(ManagedPolicyStore.HistoryEntry::operation).containsExactly("seed", "publish", "rollback");
        assertThat(store.history().get(2).requestedBy()).isEqualTo("bob");
        assertThatThrownBy(() -> store.rollback("v9", v1, "agent:admin", "bob"))
            .isInstanceOfSatisfying(PolicyChangeException.class, ex -> assertThat(ex.code()).isEqualTo(PolicyChangeException.VERSION_NOT_FOUND));
    }

    @Test
    void aRollbackSurvivesARestartEvenWithTheSeedFileUnchanged() {
        Path seed = writeSeed(policy("v1", "incident_id"));
        VersionedPolicyStore store = store(seed);
        Change v2 = store.publish(policy("v2", "incident_id", "reason"), store.currentPolicy().orElseThrow().hash(), "agent:admin", "alice");
        store.rollback("v1", v2.hash(), "agent:admin", "alice");
        store.publish(policy("v3", "incident_id", "credential_id"), store.currentPolicy().orElseThrow().hash(), "agent:admin", "alice");

        assertThat(store(seed).currentPolicy().orElseThrow().version()).isEqualTo("v3");
    }

    @Test
    void aSeedWithANewVersionIsPublishedOnRestart() {
        Path seed = writeSeed(policy("v1", "incident_id"));
        store(seed);
        writeSeed(policy("v2", "incident_id", "reason"));

        VersionedPolicyStore restarted = store(seed);

        assertThat(restarted.currentPolicy().orElseThrow().version()).isEqualTo("v2");
        assertThat(restarted.history()).extracting(ManagedPolicyStore.HistoryEntry::operation).containsExactly("seed", "seed");
    }

    @Test
    void versionNamesThatDifferOnlyByCaseOrUseColonsAreStoredSeparately() {
        VersionedPolicyStore store = store(writeSeed(policy("Release:1", "incident_id")));
        store.publish(policy("release:1", "incident_id", "reason"), store.currentPolicy().orElseThrow().hash(), "agent:admin", "alice");

        assertThat(store.version("Release:1").orElseThrow().document().actions().get("revoke-credential").allowedFields()).containsExactly("incident_id");
        assertThat(store.version("release:1").orElseThrow().document().actions().get("revoke-credential").allowedFields())
            .containsExactly("incident_id", "reason");
        assertThat(store.version("../escape")).isEmpty();
    }

    @Test
    void anEditedHistoryStopsStartup() throws IOException {
        Path seed = writeSeed(policy("v1", "incident_id"));
        VersionedPolicyStore store = store(seed);
        store.publish(policy("v2", "incident_id", "reason"), store.currentPolicy().orElseThrow().hash(), "agent:admin", "alice");
        Path history = temp.resolve("policy/history.jsonl");
        Files.writeString(history, Files.readString(history).replace("alice", "mallory"));

        assertThatThrownBy(() -> store(seed)).isInstanceOf(IllegalStateException.class).hasMessageContaining("hash chain is broken");
    }

    @Test
    void aReplacedVersionFileStopsStartup() throws IOException {
        Path seed = writeSeed(policy("v1", "incident_id"));
        store(seed);
        try (var files = Files.list(temp.resolve("policy/versions"))) {
            Path stored = files.findFirst().orElseThrow();
            Files.write(stored, policy("v1", "incident_id", "reason"));
        }

        assertThatThrownBy(() -> store(seed)).isInstanceOf(IllegalStateException.class).hasMessageContaining("does not match its recorded hash");
    }

    @Test
    void withoutSeedOrHistoryThereIsNoPolicyUntilOneIsPublished() {
        VersionedPolicyStore store = store(temp.resolve("missing.json"));
        assertThat(store.current()).isEmpty();

        store.publish(policy("v1", "incident_id"), null, "agent:admin", "alice");

        assertThat(PolicyDocumentParser.parse(store.current().orElseThrow()).version()).isEqualTo("v1");
    }

    private VersionedPolicyStore store(Path seed) {
        return new VersionedPolicyStore(temp.resolve("policy"), seed, MAPPER, CLOCK);
    }

    private Path writeSeed(byte[] document) {
        try {
            Path seed = temp.resolve("seed.json");
            Files.write(seed, document);
            return seed;
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static byte[] policy(String version, String... revokeFields) {
        String fields = String.join("\",\"", List.of(revokeFields));
        return ("""
            {"version":"%s","actions":{"revoke-credential":{"purpose":"incident-remediation","allowed_fields":["%s"],
            "allowed_hosts":["security.example"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}}}"""
            .formatted(version, fields)).getBytes(StandardCharsets.UTF_8);
    }
}
