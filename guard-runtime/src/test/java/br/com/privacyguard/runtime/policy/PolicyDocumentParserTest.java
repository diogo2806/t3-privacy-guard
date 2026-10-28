package br.com.privacyguard.runtime.policy;

import static br.com.privacyguard.runtime.policy.PolicyFixtures.BASELINE_POLICY;
import static br.com.privacyguard.runtime.policy.PolicyFixtures.policy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class PolicyDocumentParserTest {
    private static final String REVOKE_RULE = """
        {"purpose":"incident-remediation","allowed_fields":["incident_id","credential_id","reason"],"allowed_hosts":["postman-echo.com"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}""";

    /*
     * Golden hashes were computed by the original TypeScript policy canonicalizer, whose output for these documents
     * was byte-identical to the Rust contract this runtime replaces (both are kept under the dual-runtime git tag).
     */
    @Test
    void repositoryPolicyHashMatchesTheOriginalCanonicalizer() throws Exception {
        byte[] bytes = Files.readAllBytes(Path.of("policy/privacy-guard-policy.json"));
        AppliedPolicy applied = PolicyDocumentParser.parse(bytes);
        assertThat(applied.version()).isEqualTo("2026-09-16.1");
        assertThat(applied.hash()).isEqualTo("b0bbf68eb05dcb056076b3957ab512f31729cc0869a9d5162deaf11f034c42da");
    }

    @Test
    void rustTestBaselineHashMatchesTheOriginalCanonicalizer() {
        assertThat(policy(BASELINE_POLICY).hash()).isEqualTo("dde59f46121923b8c7c3a75c1857307714c4078f1e46ee029d14b683a1d81531");
    }

    @Test
    void canonicalizationNormalizesAndSortsLikeTheContract() {
        AppliedPolicy applied = policy("""
            {"version":"  v1  ","actions":{"revoke-credential":{"purpose":" Incident-Remediation ","allowed_fields":["Reason"," incident_id","CREDENTIAL_ID"],"allowed_hosts":["Security-API.internal"],"requires_host":true,"requires_human_authorization":true}}}""");
        assertThat(new String(PolicyDocumentParser.canonicalBytes(applied.document()), StandardCharsets.UTF_8)).isEqualTo(
            "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"incident-remediation\","
                + "\"allowed_fields\":[\"credential_id\",\"incident_id\",\"reason\"],\"allowed_hosts\":[\"security-api.internal\"],"
                + "\"allowed_private_refs\":[],\"requires_host\":true,\"requires_human_authorization\":true}}}");
        assertThat(applied.hash()).isEqualTo("9bda512b2764a9c92712aab37734e7c2e1ec72c2e7ae66bf44bca396983ab700");
    }

    @Test
    void forbiddenSecretCannotBeEnabledByExternalPolicy() {
        assertInvalid("""
            {"version":"v1","actions":{"revoke-credential":{"purpose":"incident-remediation","allowed_fields":["incident_id","api_key"],"allowed_hosts":["postman-echo.com"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}}}""");
    }

    @Test
    void canonicalHashIsStableAndChangesWithPolicyContent() throws Exception {
        AppliedPolicy first = policy(BASELINE_POLICY);
        assertThat(policy(BASELINE_POLICY).hash()).isEqualTo(first.hash());

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode value = (ObjectNode) mapper.readTree(BASELINE_POLICY);
        ((ObjectNode) value.at("/actions/revoke-credential")).putArray("allowed_hosts").add("security-api.internal");
        assertThat(PolicyDocumentParser.parse(mapper.writeValueAsBytes(value)).hash()).isNotEqualTo(first.hash());
    }

    @Test
    void duplicateNormalizedValuesAreRejected() {
        assertInvalid("""
            {"version":"v1","actions":{"revoke-credential":{"purpose":"incident-remediation","allowed_fields":["reason"," REASON "],"allowed_hosts":["postman-echo.com"],"allowed_private_refs":[],"requires_host":true,"requires_human_authorization":true}}}""");
    }

    @Test
    void actionNamesMustBeCanonicalAndUniqueAfterNormalization() {
        assertInvalid("{\"version\":\"v1\",\"actions\":{\"Revoke-Credential\":" + REVOKE_RULE + "}}");
        assertInvalid("{\"version\":\"v1\",\"actions\":{\" revoke-credential\":" + REVOKE_RULE + ",\"revoke-credential\":" + REVOKE_RULE + "}}");
        // Surrounding whitespace alone is tolerated by the contract and trimmed away.
        assertThat(policy("{\"version\":\"v1\",\"actions\":{\" revoke-credential \":" + REVOKE_RULE + "}}").document().actions())
            .containsOnlyKeys("revoke-credential");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":" + REVOKE_RULE + "},\"extra\":1}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"incident-remediation\",\"allowed_hosts\":[\"postman-echo.com\"],\"requires_host\":true,\"extra\":1}}}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"incident-remediation\",\"allowed_hosts\":[\"postman-echo.com\"]}}}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"incident-remediation\",\"allowed_hosts\":[\"postman-echo.com\"],\"requires_host\":\"true\"}}}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"incident-remediation\",\"allowed_hosts\":[\"postman-echo.com\"],\"requires_host\":true,\"requires_human_authorization\":null}}}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"incident-remediation\",\"allowed_fields\":null,\"allowed_hosts\":[\"postman-echo.com\"],\"requires_host\":true}}}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"incident-remediation\",\"allowed_fields\":[1],\"allowed_hosts\":[\"postman-echo.com\"],\"requires_host\":true}}}",
        "{\"version\":1,\"actions\":{\"revoke-credential\":" + REVOKE_RULE + "}}",
        "{\"version\":\"v1\",\"actions\":[]}",
        "{\"version\":\"v1\",\"version\":\"v2\",\"actions\":{\"revoke-credential\":" + REVOKE_RULE + "}}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":" + REVOKE_RULE + "}} trailing",
        "[\"v1\",{}]",
        "{\"version\":\"v1\\ud800\",\"actions\":{\"revoke-credential\":" + REVOKE_RULE + "}}",
    })
    void malformedOrMistypedDocumentsAreRejected(String json) {
        assertInvalid(json);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "{\"version\":\"v 1\",\"actions\":{\"revoke-credential\":" + REVOKE_RULE + "}}",
        "{\"version\":\"v1\",\"actions\":{}}",
        "{\"version\":\"v1\",\"actions\":{\"create-incident\":{\"purpose\":\"incident-recording\",\"allowed_hosts\":[\"postman-echo.com\"],\"requires_host\":false}}}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"incident-remediation\",\"requires_host\":true}}}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"incident-remediation\",\"allowed_hosts\":[\"postman-echo.com:443\"],\"requires_host\":true}}}",
        "{\"version\":\"v1\",\"actions\":{\"notify-security\":{\"purpose\":\"incident-notification\",\"allowed_hosts\":[\"postman-echo.com\"],\"allowed_private_refs\":[\"home_address\"],\"requires_host\":true}}}",
        "{\"version\":\"v1\",\"actions\":{\"revoke-credential\":{\"purpose\":\"   \",\"allowed_hosts\":[\"postman-echo.com\"],\"requires_host\":true}}}",
    })
    void semanticallyInvalidDocumentsAreRejected(String json) {
        assertInvalid(json);
    }

    @Test
    void actionCountIsLimited() {
        StringBuilder actions = new StringBuilder();
        for (int i = 0; i < 17; i++) {
            if (i > 0) actions.append(',');
            actions.append("\"action-").append(i).append("\":{\"purpose\":\"p\",\"requires_host\":false}");
        }
        assertInvalid("{\"version\":\"v1\",\"actions\":{" + actions + "}}");
    }

    @Test
    void emptyOrOversizedDocumentsAreRejected() {
        assertThatThrownBy(() -> PolicyDocumentParser.parse(new byte[0])).isInstanceOf(PolicyDocumentException.class);
        String padded = BASELINE_POLICY + " ".repeat(PolicyDocumentParser.MAX_POLICY_BYTES);
        assertInvalid(padded);
    }

    @Test
    void invalidUtf8IsRejected() {
        byte[] bytes = "{\"version\":\"v1\",\"actions\":{}}".getBytes(StandardCharsets.UTF_8);
        bytes[13] = (byte) 0xFF;
        assertThatThrownBy(() -> PolicyDocumentParser.parse(bytes)).isInstanceOf(PolicyDocumentException.class);
    }

    @Test
    void lengthLimitsCountUtf8Bytes() {
        String accepted = "é".repeat(40);
        String rejected = "é".repeat(41);
        String template = "{\"version\":\"v1\",\"actions\":{\"create-incident\":{\"purpose\":\"incident-recording\",\"allowed_fields\":[\"%s\"],\"requires_host\":false}}}";
        assertThat(policy(template.formatted(accepted)).document().actions().get("create-incident").allowedFields()).containsExactly(accepted);
        assertInvalid(template.formatted(rejected));
    }

    @Test
    void canonicalJsonEscapesControlCharactersLikeSerde() {
        AppliedPolicy applied = policy("""
            {"version":"v1","actions":{"create-incident":{"purpose":"incident\\u0001\\u001frecording\\t","allowed_fields":["a\\"b\\\\c/é"],"requires_host":false}}}""");
        String canonical = new String(PolicyDocumentParser.canonicalBytes(applied.document()), StandardCharsets.UTF_8);
        // The trailing tab is trimmed; interior control characters use lowercase \\u00xx; '/' and non-ASCII stay raw.
        assertThat(canonical).contains("\"purpose\":\"incident\\u0001\\u001frecording\"");
        assertThat(canonical).contains("\"allowed_fields\":[\"a\\\"b\\\\c/é\"]");
    }

    @Test
    void listsAreSortedByCodePoint() {
        AppliedPolicy applied = policy("""
            {"version":"v1","actions":{"create-incident":{"purpose":"incident-recording","allowed_fields":["😀x","\\ue000x","zeta"],"requires_host":false}}}""");
        assertThat(applied.document().actions().get("create-incident").allowedFields()).containsExactly("zeta", "x", "😀x");
    }

    private static void assertInvalid(String json) {
        assertThatThrownBy(() -> PolicyDocumentParser.parse(json.getBytes(StandardCharsets.UTF_8))).isInstanceOf(PolicyDocumentException.class);
    }
}
