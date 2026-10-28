package br.com.privacyguard.runtime.policy;

import static br.com.privacyguard.runtime.policy.PolicyFixtures.FORBIDDEN;
import static br.com.privacyguard.runtime.policy.PolicyFixtures.PROPERTY_POLICY;
import static br.com.privacyguard.runtime.policy.PolicyFixtures.T3N_DID;
import static br.com.privacyguard.runtime.policy.PolicyFixtures.allowedRequest;
import static org.assertj.core.api.Assertions.assertThat;

import br.com.privacyguard.runtime.contract.InvalidContractInputException;
import br.com.privacyguard.runtime.policy.PolicyDecision.Decision;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Port of tests/properties.rs. Small input spaces are enumerated exhaustively; generated strings use a fixed seed
 * and the same 512 cases proptest ran, so a failure is reproducible.
 */
class PolicyEvaluatorPropertiesTest {
    private static final AppliedPolicy POLICY = PolicyFixtures.policy(PROPERTY_POLICY);
    private static final int CASES = 512;
    private static final Map<String, Set<String>> EXPECTED_FIELDS = Map.of(
        "revoke-credential", Set.of("incident_id", "credential_id", "reason"),
        "isolate-account", Set.of("incident_id", "account_id", "reason"),
        "create-incident", Set.of("incident_id", "severity", "summary", "source"),
        "notify-security", Set.of("incident_id", "severity", "summary")
    );

    private static PolicyDecision evaluate(PolicyFixtures.Request request) {
        return PolicyEvaluator.evaluate(request.build(), POLICY, T3N_DID);
    }

    @Test
    void forbiddenSecretIsNeverAllowed() {
        for (int action = 0; action < 4; action++) {
            for (String secret : FORBIDDEN) {
                for (int duplicates = 1; duplicates < 6; duplicates++) {
                    PolicyFixtures.Request request = allowedRequest(action);
                    for (int i = 0; i < duplicates; i++) request.fields.add(secret);
                    PolicyDecision decision = evaluate(request);
                    assertThat(decision.decision()).isEqualTo(Decision.DENY);
                    assertThat(decision.reasonCode()).isEqualTo("SECRET_DISCLOSURE_FORBIDDEN");
                    assertThat(decision.allowedFields()).doesNotContain(secret);
                }
            }
        }
    }

    @Test
    void allowImpliesCompleteActionPolicy() {
        for (int action = 0; action < 4; action++) {
            for (int duplicates = 0; duplicates < 5; duplicates++) {
                PolicyFixtures.Request request = allowedRequest(action);
                String first = request.fields.get(0);
                for (int i = 0; i < duplicates; i++) request.fields.add(first);
                PolicyDecision decision = evaluate(request);
                assertThat(decision.decision()).isEqualTo(Decision.ALLOW);
                assertThat(decision.policyVersion()).isNotNull();
                assertThat(decision.policyHash()).isNotNull();
                assertThat(EXPECTED_FIELDS.get(request.action)).containsAll(decision.allowedFields());
                assertThat(decision.allowedFields()).doesNotContainAnyElementsOf(FORBIDDEN);
                assertThat(decision.redactedFields()).isEmpty();
                assertThat(decision.redactedPrivateRefs()).isEmpty();
                if (request.action.equals("notify-security")) {
                    assertThat(decision.allowedPrivateRefs()).containsExactly("verified_email");
                } else {
                    assertThat(decision.allowedPrivateRefs()).isEmpty();
                }
            }
        }
    }

    @Test
    void privilegeIncreaseNeverImprovesAnAllowedDecision() {
        Random random = new Random(20260912L);
        for (int i = 0; i < CASES; i++) {
            PolicyFixtures.Request request = allowedRequest(random.nextInt(4));
            assertThat(evaluate(request).decision()).isEqualTo(Decision.ALLOW);
            switch (random.nextInt(4)) {
                case 0 -> request.fields.add("extra_" + generate(random, "abcdefghijklmnopqrstuvwxyz0123456789_", 1, 24));
                case 1 -> request.fields.add("api_key");
                case 2 -> request.privateRefs.add("unknown_private_ref");
                default -> request.purpose = "unrelated-purpose";
            }
            assertThat(evaluate(request).decision()).isNotEqualTo(Decision.ALLOW);
        }
    }

    @Test
    void normalizationCannotHideForbiddenSecret() {
        for (int action = 0; action < 4; action++) {
            for (String secret : FORBIDDEN) {
                for (int leading = 0; leading < 5; leading++) {
                    for (int trailing = 0; trailing < 5; trailing++) {
                        for (boolean uppercase : List.of(false, true)) {
                            PolicyFixtures.Request request = allowedRequest(action);
                            String value = uppercase ? secret.toUpperCase() : secret;
                            request.fields.add(" ".repeat(leading) + value + " ".repeat(trailing));
                            PolicyDecision decision = evaluate(request);
                            assertThat(decision.decision()).isEqualTo(Decision.DENY);
                            assertThat(decision.reasonCode()).isEqualTo("SECRET_DISCLOSURE_FORBIDDEN");
                        }
                    }
                }
            }
        }
    }

    @Test
    void arbitraryInputNeverEscapesAsAnUnexpectedException() {
        Random random = new Random(42L);
        for (int i = 0; i < CASES; i++) {
            byte[] input = new byte[random.nextInt(4096)];
            random.nextBytes(input);
            try {
                PolicyEvaluator.parseRequest(input);
            } catch (InvalidContractInputException expected) {
                // Fail-closed rejection is the only acceptable failure.
            }
        }
    }

    @Test
    void rawOrUnknownPrivateReferenceNeverBecomesAllowed() {
        Random random = new Random(7L);
        for (int i = 0; i < CASES; i++) {
            PolicyFixtures.Request request = allowedRequest(random.nextInt(4));
            String generated = generate(random, "abcdefghijklmnopqrstuvwxyz", 1, 1)
                + generate(random, "abcdefghijklmnopqrstuvwxyz0123456789_", 1, 40);
            String privateRef = generated.equals("verified_email") ? "not_verified_email" : generated;
            request.privateRefs.add(privateRef);
            PolicyDecision decision = evaluate(request);
            assertThat(decision.decision()).isNotEqualTo(Decision.ALLOW);
            assertThat(decision.allowedPrivateRefs()).doesNotContain(privateRef);
        }
    }

    private static String generate(Random random, String alphabet, int minLength, int maxLength) {
        int length = minLength + random.nextInt(maxLength - minLength + 1);
        StringBuilder out = new StringBuilder(length);
        for (int i = 0; i < length; i++) out.append(alphabet.charAt(random.nextInt(alphabet.length())));
        return out.toString();
    }
}
