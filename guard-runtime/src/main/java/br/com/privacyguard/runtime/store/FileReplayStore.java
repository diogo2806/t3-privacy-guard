package br.com.privacyguard.runtime.store;

import br.com.privacyguard.runtime.authorization.AuthorizationClaims;
import br.com.privacyguard.runtime.authorization.ReplayBucket;
import br.com.privacyguard.runtime.authorization.ReplayStore;
import br.com.privacyguard.runtime.contract.ContractRejectedException;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Nonce buckets in one JSON file, read-modify-write under a lock and replaced atomically. Correct for a single
 * runtime instance; several instances need a shared transactional store instead.
 */
@Component
public class FileReplayStore implements ReplayStore {
    private static final TypeReference<Map<String, StoredBucket>> STORED = new TypeReference<>() {};

    private final Path file;
    private final ObjectMapper mapper;

    public FileReplayStore(@Value("${guard-runtime.replay-file:}") String file, ObjectMapper mapper) {
        if (file == null || file.isBlank()) throw new IllegalStateException("guard-runtime.replay-file is required");
        this.file = Path.of(file.trim()).toAbsolutePath().normalize();
        this.mapper = mapper;
    }

    @Override
    public synchronized void consume(AuthorizationClaims claims, long nowMs) {
        Map<String, StoredBucket> buckets = read();
        String slot = ReplayBucket.slotKey(claims);
        StoredBucket stored = buckets.get(slot);
        ReplayBucket current = stored == null ? ReplayBucket.empty() : stored.toBucket();
        buckets.put(slot, StoredBucket.from(current.consume(claims, nowMs)));
        write(buckets);
    }

    private Map<String, StoredBucket> read() {
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(file);
        } catch (NoSuchFileException ex) {
            return new LinkedHashMap<>();
        } catch (IOException ex) {
            throw new ContractRejectedException("authorization replay store is unavailable");
        }
        try {
            return new LinkedHashMap<>(mapper.readValue(bytes, STORED));
        } catch (IOException ex) {
            throw new ContractRejectedException("authorization replay store is invalid");
        }
    }

    private void write(Map<String, StoredBucket> buckets) {
        try {
            Files.createDirectories(file.getParent());
            Path temporary = file.resolveSibling(file.getFileName() + ".tmp-" + UUID.randomUUID());
            Files.write(temporary, mapper.writeValueAsBytes(buckets));
            try {
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException ex) {
            throw new ContractRejectedException("authorization replay state could not be persisted");
        }
    }

    /** Same JSON shape the contract stored in T3N KV. */
    private record StoredBucket(long epoch, List<StoredEntry> entries) {
        static StoredBucket from(ReplayBucket bucket) {
            return new StoredBucket(bucket.epoch(), bucket.entries().stream()
                .map(entry -> new StoredEntry(entry.nonceHash(), entry.expiresAt())).toList());
        }

        ReplayBucket toBucket() {
            return new ReplayBucket(epoch, entries == null ? List.of() : entries.stream()
                .map(entry -> new ReplayBucket.Entry(entry.nonceHash(), entry.expiresAt())).toList());
        }
    }

    private record StoredEntry(@JsonProperty("nonce_hash") String nonceHash, @JsonProperty("expires_at") long expiresAt) {}
}
