package br.com.privacyguard.runtime.store;

import br.com.privacyguard.runtime.policy.AppliedPolicy;
import br.com.privacyguard.runtime.policy.PolicyDocumentException;
import br.com.privacyguard.runtime.policy.PolicyDocumentParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Policy versions under {@code <dir>/versions} (canonical bytes, written once, never replaced) and the history of which
 * version became current, as hash-chained JSON lines in {@code <dir>/history.jsonl}. The current policy is the version
 * named by the last history entry. On startup the chain and the current version's hash are re-verified; a mismatch
 * stops the runtime.
 *
 * <p>The optional seed file is how an operator still manages policy as a file: a seed whose version is not known yet
 * is published on startup. A known version is left alone, so a rollback done at runtime survives a restart.
 */
public final class VersionedPolicyStore implements ManagedPolicyStore {
    static final String SEED_CALLER = "seed-file";
    private static final String GENESIS = "0".repeat(64);
    private static final Logger LOG = LoggerFactory.getLogger(VersionedPolicyStore.class);

    private final Path versions;
    private final Path historyFile;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final List<HistoryEntry> history = new ArrayList<>();
    private AppliedPolicy current;
    private byte[] currentBytes;

    public VersionedPolicyStore(Path directory, Path seedFile, ObjectMapper mapper, Clock clock) {
        Path root = directory.toAbsolutePath().normalize();
        this.versions = root.resolve("versions");
        this.historyFile = root.resolve("history.jsonl");
        this.mapper = mapper;
        this.clock = clock;
        load();
        if (seedFile != null) seed(seedFile.toAbsolutePath().normalize());
    }

    @Override
    public synchronized Optional<byte[]> current() {
        return Optional.ofNullable(currentBytes).map(byte[]::clone);
    }

    @Override
    public synchronized Optional<AppliedPolicy> currentPolicy() {
        return Optional.ofNullable(current);
    }

    @Override
    public synchronized Optional<AppliedPolicy> version(String version) {
        if (!PolicyDocumentParser.isValidVersion(version)) return Optional.empty();
        return readVersion(version);
    }

    @Override
    public synchronized List<HistoryEntry> history() {
        return List.copyOf(history);
    }

    @Override
    public synchronized Change publish(byte[] document, String expectedCurrentHash, String callerId, String requestedBy) {
        AppliedPolicy candidate;
        try {
            candidate = PolicyDocumentParser.parse(document);
        } catch (PolicyDocumentException ex) {
            throw new PolicyChangeException(PolicyChangeException.POLICY_INVALID, ex.getMessage());
        }
        requireExpectedCurrent(expectedCurrentHash);
        if (current != null && current.version().equals(candidate.version()) && current.hash().equals(candidate.hash())) {
            return unchanged();
        }
        if (Files.exists(versionFile(candidate.version()))) {
            throw new PolicyChangeException(PolicyChangeException.VERSION_EXISTS,
                "version " + candidate.version() + " was already published; choose a new version or roll back to it");
        }
        writeVersion(candidate);
        return makeCurrent("publish", candidate, callerId, requestedBy);
    }

    @Override
    public synchronized Change rollback(String version, String expectedCurrentHash, String callerId, String requestedBy) {
        requireExpectedCurrent(expectedCurrentHash);
        AppliedPolicy target = version(version).orElseThrow(() ->
            new PolicyChangeException(PolicyChangeException.VERSION_NOT_FOUND, "version was never published"));
        if (current != null && current.version().equals(target.version())) return unchanged();
        return makeCurrent("rollback", target, callerId, requestedBy);
    }

    private void requireExpectedCurrent(String expectedCurrentHash) {
        String currentHash = current == null ? null : current.hash();
        if (!Objects.equals(currentHash, expectedCurrentHash)) {
            throw new PolicyChangeException(PolicyChangeException.POLICY_CHANGED, "the current policy changed since it was read");
        }
    }

    private Change unchanged() {
        return new Change(false, current.version(), current.hash(), current.version(), current.hash());
    }

    private Change makeCurrent(String operation, AppliedPolicy next, String callerId, String requestedBy) {
        String previousVersion = current == null ? null : current.version();
        String previousHash = current == null ? null : current.hash();
        long sequence = history.size() + 1L;
        String previousEntryHash = history.isEmpty() ? GENESIS : history.get(history.size() - 1).entryHash();
        HistoryEntry unsigned = new HistoryEntry(sequence, "", clock.millis(), operation, next.version(), next.hash(),
            previousVersion, previousHash, callerId, requestedBy);
        HistoryEntry entry = withHash(unsigned, chainHash(previousEntryHash, unsigned));
        try {
            Files.createDirectories(historyFile.getParent());
            Files.write(historyFile, (mapper.writeValueAsString(entry) + "\n").getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ex) {
            throw new UncheckedIOException("policy history could not be persisted", ex);
        }
        history.add(entry);
        current = next;
        currentBytes = PolicyDocumentParser.canonicalBytes(next.document());
        return new Change(true, next.version(), next.hash(), previousVersion, previousHash);
    }

    private void load() {
        List<String> lines;
        try {
            lines = Files.readAllLines(historyFile, StandardCharsets.UTF_8);
        } catch (NoSuchFileException ex) {
            return;
        } catch (IOException ex) {
            throw new IllegalStateException("policy history is unreadable", ex);
        }
        String previous = GENESIS;
        for (String line : lines) {
            if (line.isBlank()) continue;
            HistoryEntry entry;
            try {
                entry = mapper.readValue(line, HistoryEntry.class);
            } catch (IOException ex) {
                throw new IllegalStateException("policy history contains an unreadable entry");
            }
            long expectedSequence = history.size() + 1L;
            if (entry.sequence() != expectedSequence || !chainHash(previous, entry).equals(entry.entryHash())) {
                throw new IllegalStateException("policy history hash chain is broken at sequence " + expectedSequence);
            }
            history.add(entry);
            previous = entry.entryHash();
        }
        if (history.isEmpty()) return;
        HistoryEntry last = history.get(history.size() - 1);
        AppliedPolicy policy = readVersion(last.version())
            .orElseThrow(() -> new IllegalStateException("current policy version " + last.version() + " is missing"));
        if (!policy.hash().equals(last.policyHash())) {
            throw new IllegalStateException("current policy version " + last.version() + " does not match its recorded hash");
        }
        current = policy;
        currentBytes = PolicyDocumentParser.canonicalBytes(policy.document());
    }

    private void seed(Path seedFile) {
        byte[] bytes;
        try (InputStream in = Files.newInputStream(seedFile)) {
            bytes = in.readNBytes(PolicyDocumentParser.MAX_POLICY_BYTES + 1);
        } catch (NoSuchFileException ex) {
            return;
        } catch (IOException ex) {
            LOG.warn("Seed policy file is unreadable; ignored");
            return;
        }
        AppliedPolicy seed;
        try {
            seed = PolicyDocumentParser.parse(bytes);
        } catch (PolicyDocumentException ex) {
            LOG.warn("Seed policy file is invalid ({}); ignored", ex.getMessage());
            return;
        }
        Optional<AppliedPolicy> known = readVersion(seed.version());
        if (known.isPresent()) {
            if (!known.get().hash().equals(seed.hash())) {
                LOG.warn("Seed policy file reuses published version {} with different content; ignored", seed.version());
            }
            return;
        }
        writeVersion(seed);
        makeCurrent("seed", seed, SEED_CALLER, null);
    }

    private Optional<AppliedPolicy> readVersion(String version) {
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(versionFile(version));
        } catch (NoSuchFileException ex) {
            return Optional.empty();
        } catch (IOException ex) {
            throw new UncheckedIOException("policy version is unreadable", ex);
        }
        AppliedPolicy policy;
        try {
            policy = PolicyDocumentParser.parse(bytes);
        } catch (PolicyDocumentException ex) {
            throw new IllegalStateException("stored policy version " + version + " is invalid");
        }
        if (!policy.version().equals(version)) throw new IllegalStateException("stored policy version " + version + " names another version");
        return Optional.of(policy);
    }

    private void writeVersion(AppliedPolicy policy) {
        Path target = versionFile(policy.version());
        try {
            Files.createDirectories(versions);
            Path temporary = Files.createTempFile(versions, "publish-", ".tmp");
            Files.write(temporary, PolicyDocumentParser.canonicalBytes(policy.document()));
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException ex) {
            throw new UncheckedIOException("policy version could not be persisted", ex);
        }
    }

    /** Hex of the version's bytes: ":" is not allowed in Windows file names and "A1"/"a1" would collide there. */
    private Path versionFile(String version) {
        return versions.resolve(HexFormat.of().formatHex(version.getBytes(StandardCharsets.UTF_8)) + ".json");
    }

    private static HistoryEntry withHash(HistoryEntry entry, String hash) {
        return new HistoryEntry(entry.sequence(), hash, entry.timestampMs(), entry.operation(), entry.version(), entry.policyHash(),
            entry.previousVersion(), entry.previousPolicyHash(), entry.caller(), entry.requestedBy());
    }

    static String chainHash(String previous, HistoryEntry entry) {
        String material = String.join("\n", previous, Long.toString(entry.sequence()), Long.toString(entry.timestampMs()),
            entry.operation(), entry.version(), entry.policyHash(), Objects.toString(entry.previousVersion(), ""),
            Objects.toString(entry.previousPolicyHash(), ""), entry.caller(), Objects.toString(entry.requestedBy(), ""));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }
}
