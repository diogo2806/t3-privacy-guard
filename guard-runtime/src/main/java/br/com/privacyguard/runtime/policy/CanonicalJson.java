package br.com.privacyguard.runtime.policy;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Byte-exact equivalent of serde_json::to_vec over the Rust PolicyDocument: compact, struct field order, short
 * escapes for \b \f \n \r \t, lowercase \\u00xx for other control characters, everything else written raw.
 * The policy hash is SHA-256 over these bytes, so a generic JSON writer is not good enough.
 */
final class CanonicalJson {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private CanonicalJson() {}

    static byte[] policyDocument(PolicyDocument document) {
        StringBuilder out = new StringBuilder(1024);
        out.append("{\"version\":");
        string(out, document.version());
        out.append(",\"actions\":{");
        boolean first = true;
        for (Map.Entry<String, PolicyDocument.ActionPolicy> entry : document.actions().entrySet()) {
            if (!first) out.append(',');
            first = false;
            PolicyDocument.ActionPolicy rule = entry.getValue();
            string(out, entry.getKey());
            out.append(":{\"purpose\":");
            string(out, rule.purpose());
            out.append(",\"allowed_fields\":");
            array(out, rule.allowedFields());
            out.append(",\"allowed_hosts\":");
            array(out, rule.allowedHosts());
            out.append(",\"allowed_private_refs\":");
            array(out, rule.allowedPrivateRefs());
            out.append(",\"requires_host\":").append(rule.requiresHost());
            out.append(",\"requires_human_authorization\":").append(rule.requiresHumanAuthorization());
            out.append('}');
        }
        out.append("}}");
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void array(StringBuilder out, List<String> values) {
        out.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) out.append(',');
            string(out, values.get(i));
        }
        out.append(']');
    }

    private static void string(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            switch (current) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (current < 0x20) {
                        out.append("\\u00").append(HEX[current >> 4]).append(HEX[current & 0xF]);
                    } else {
                        out.append(current);
                    }
                }
            }
        }
        out.append('"');
    }
}
