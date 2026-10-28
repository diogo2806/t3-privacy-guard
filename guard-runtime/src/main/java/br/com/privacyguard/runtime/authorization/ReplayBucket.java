package br.com.privacyguard.runtime.authorization;

import br.com.privacyguard.runtime.contract.ContractRejectedException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** One slot of the nonce replay store, same layout and limits as authorization.rs. */
public record ReplayBucket(long epoch, List<Entry> entries) {
    public static final long BUCKET_MS = 60_000;
    public static final long SLOTS = 8;
    private static final int MAX_ENTRIES = 1_024;

    public ReplayBucket {
        entries = List.copyOf(entries);
    }

    public record Entry(String nonceHash, long expiresAt) {}

    public static ReplayBucket empty() {
        return new ReplayBucket(0, List.of());
    }

    public static String slotKey(AuthorizationClaims claims) {
        return "slot-" + ((claims.expiresAt() / BUCKET_MS) % SLOTS);
    }

    public ReplayBucket consume(AuthorizationClaims claims, long nowMs) {
        long bucketEpoch = claims.expiresAt() / BUCKET_MS;
        String nonceHash = CapabilityHashes.sha256Hex(claims.nonce().getBytes(StandardCharsets.UTF_8));
        List<Entry> live = new ArrayList<>();
        if (epoch == bucketEpoch) {
            for (Entry entry : entries) if (entry.expiresAt() > nowMs) live.add(entry);
        }
        if (live.stream().anyMatch(entry -> entry.nonceHash().equals(nonceHash))) {
            throw new ContractRejectedException("authorization proof replay detected");
        }
        if (live.size() >= MAX_ENTRIES) throw new ContractRejectedException("authorization replay bucket capacity exceeded");
        live.add(new Entry(nonceHash, claims.expiresAt()));
        return new ReplayBucket(bucketEpoch, live);
    }
}
