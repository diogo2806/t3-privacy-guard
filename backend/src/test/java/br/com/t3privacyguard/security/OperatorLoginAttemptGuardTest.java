package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import org.junit.jupiter.api.Test;

class OperatorLoginAttemptGuardTest {
    @Test
    void thresholdStartsCooldownAndSuccessResetsFailureState() {
        MutableClock clock = new MutableClock(Instant.parse("2026-09-12T22:00:00Z"));
        OperatorLoginAttemptGuard guard = new OperatorLoginAttemptGuard(clock);

        for (int failure = 1; failure < OperatorLoginAttemptGuard.FAILURE_THRESHOLD; failure++) {
            guard.recordFailure(" Operator ");
        }

        assertThatThrownBy(() -> guard.recordFailure("operator"))
            .isInstanceOfSatisfying(TooManyLoginAttemptsException.class, error ->
                assertThat(error.retryAfterSeconds()).isEqualTo(OperatorLoginAttemptGuard.BASE_COOLDOWN.toSeconds()));
        assertThatThrownBy(() -> guard.assertAllowed("OPERATOR"))
            .isInstanceOf(TooManyLoginAttemptsException.class);

        clock.advance(OperatorLoginAttemptGuard.BASE_COOLDOWN);
        guard.assertAllowed("operator");
        guard.recordSuccess("operator");
        guard.assertAllowed("operator");
    }

    @Test
    void randomUsernamesCannotGrowTrackingMemoryWithoutBound() {
        OperatorLoginAttemptGuard guard = new OperatorLoginAttemptGuard();
        for (int index = 0; index < OperatorLoginAttemptGuard.MAX_TRACKED_IDENTITIES + 50; index++) {
            guard.recordFailure("random-user-" + index);
        }
        assertThat(guard.trackedIdentityCount()).isEqualTo(OperatorLoginAttemptGuard.MAX_TRACKED_IDENTITIES);
    }

    private static final class MutableClock extends Clock {
        private Instant current;

        private MutableClock(Instant current) {
            this.current = current;
        }

        private void advance(Duration duration) {
            current = current.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return current;
        }
    }
}
