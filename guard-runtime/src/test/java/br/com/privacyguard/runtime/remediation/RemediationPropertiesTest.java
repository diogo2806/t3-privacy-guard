package br.com.privacyguard.runtime.remediation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.privacyguard.runtime.contract.ContractRejectedException;
import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Random;
import org.junit.jupiter.api.Test;

/** Port of tests/remediation_properties.rs with fixed seeds. */
class RemediationPropertiesTest {
    private static final int CASES = 256;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void remediationParsersNeverEscapeAsUnexpectedExceptions() {
        Random random = new Random(256L);
        for (int i = 0; i < CASES; i++) {
            byte[] input = new byte[random.nextInt(4096)];
            random.nextBytes(input);
            try {
                RemediationExecutionRequest.parse(input);
            } catch (InvalidContractInputException expected) {
                // fail-closed rejection is the only acceptable failure
            }
            try {
                RemediationVerificationRequest.parse(input);
            } catch (InvalidContractInputException expected) {
                // same
            }
        }
    }

    @Test
    void verificationExpectedStateIsClosedPerAction() {
        Random random = new Random(512L);
        for (int i = 0; i < CASES; i++) {
            String action = random.nextBoolean() ? "revoke-credential" : "notify-security";
            String expected = action.equals("revoke-credential") ? "REVOKED" : "DELIVERED";
            String state = i % 4 == 0 ? expected : generate(random, "ABCDEFGHIJKLMNOPQRSTUVWXYZ_", 1, 32);
            RemediationVerificationRequest request = new RemediationVerificationRequest(
                generate(random, "abcXYZ019_-", 1, 64), generate(random, "abcXYZ019_-", 1, 64).replaceFirst("^[_-]", "a"), action, state);
            if (state.equals(expected)) {
                RemediationRules.validateVerificationRequest(request);
            } else {
                assertThatThrownBy(() -> RemediationRules.validateVerificationRequest(request))
                    .isInstanceOf(ContractRejectedException.class)
                    .hasMessageContaining("expected_state does not match");
            }
        }
    }

    @Test
    void reducedResultSchemaNeverReflectsArbitraryUpstreamSentinel() throws Exception {
        Random random = new Random(1024L);
        for (int i = 0; i < CASES; i++) {
            String sentinel = "SENTINEL_" + generate(random, "ABCxyz0189", 8, 40);
            int httpCode = 200 + random.nextInt(100);
            byte[] upstream = ("{\"operation_id\":\"property-operation\",\"authorization\":\"" + sentinel + "\",\"recipient\":\"" + sentinel + "\"}").getBytes();
            RemediationResult result = new RemediationResult("property-request", "PENDING_VERIFICATION", httpCode,
                RemediationRules.extractOperationId(upstream), "2026-09-12.1", "a".repeat(64));
            String serialized = MAPPER.writeValueAsString(result);
            assertThat(serialized).doesNotContain(sentinel);
            assertThat(serialized.toLowerCase()).doesNotContain("authorization").doesNotContain("recipient");
        }
    }

    private static String generate(Random random, String alphabet, int min, int max) {
        int length = min + random.nextInt(max - min + 1);
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; i++) out.append(alphabet.charAt(random.nextInt(alphabet.length())));
        return out.toString();
    }
}
