package br.com.t3privacyguard.security;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class OperatorLoginAttemptGuard {
    static final int MAX_TRACKED_IDENTITIES = 128;
    static final int FAILURE_THRESHOLD = 5;
    static final Duration FAILURE_WINDOW = Duration.ofMinutes(10);
    static final Duration BASE_COOLDOWN = Duration.ofSeconds(5);
    static final Duration MAX_COOLDOWN = Duration.ofSeconds(60);

    private final Map<String, AttemptState> attempts = new LinkedHashMap<>(16, 0.75f, true);

    public synchronized void assertAllowed(String username) {
        String key = normalize(username);
        AttemptState state = attempts.get(key);
        if (state == null || state.lockedUntil == null) return;
        Instant now = Instant.now();
        if (state.lockedUntil.isAfter(now)) {
            throw new TooManyLoginAttemptsException(secondsUntil(now, state.lockedUntil));
        }
    }

    public synchronized void recordFailure(String username) {
        String key = normalize(username);
        Instant now = Instant.now();
        AttemptState state = attempts.get(key);
        if (state == null || Duration.between(state.windowStartedAt, now).compareTo(FAILURE_WINDOW) > 0) {
            ensureCapacityFor(key);
            state = new AttemptState(now);
            attempts.put(key, state);
        }

        state.failures++;
        if (state.failures >= FAILURE_THRESHOLD) {
            int exponent = Math.min(state.failures - FAILURE_THRESHOLD, 4);
            long cooldownSeconds = Math.min(
                MAX_COOLDOWN.toSeconds(),
                BASE_COOLDOWN.toSeconds() * (1L << exponent)
            );
            state.lockedUntil = now.plusSeconds(cooldownSeconds);
            throw new TooManyLoginAttemptsException(cooldownSeconds);
        }
    }

    public synchronized void recordSuccess(String username) {
        attempts.remove(normalize(username));
    }

    synchronized int trackedIdentityCount() {
        return attempts.size();
    }

    private void ensureCapacityFor(String key) {
        if (attempts.containsKey(key) || attempts.size() < MAX_TRACKED_IDENTITIES) return;
        String eldest = attempts.keySet().iterator().next();
        attempts.remove(eldest);
    }

    private static String normalize(String username) {
        String value = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
        return value.length() <= 128 ? value : value.substring(0, 128);
    }

    private static long secondsUntil(Instant now, Instant lockedUntil) {
        long millis = Math.max(1, Duration.between(now, lockedUntil).toMillis());
        return Math.max(1, (millis + 999) / 1000);
    }

    private static final class AttemptState {
        private final Instant windowStartedAt;
        private int failures;
        private Instant lockedUntil;

        private AttemptState(Instant windowStartedAt) {
            this.windowStartedAt = windowStartedAt;
        }
    }
}
