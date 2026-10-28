package br.com.privacyguard.runtime.contract;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Byte-exact equivalent of serde_json's compact writer for strings and string arrays: short escapes for
 * \b \f \n \r \t, lowercase \\u00xx for other control characters, everything else written raw. Hashes over
 * canonical JSON (policy hash, capability list hashes) depend on these exact bytes.
 */
public final class CanonicalJson {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private CanonicalJson() {}

    public static byte[] stringArray(List<String> values) {
        StringBuilder out = new StringBuilder();
        appendStringArray(out, values);
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    public static void appendStringArray(StringBuilder out, List<String> values) {
        out.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) out.append(',');
            appendString(out, values.get(i));
        }
        out.append(']');
    }

    public static void appendString(StringBuilder out, String value) {
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
