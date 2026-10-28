package br.com.privacyguard.runtime.contract;

import java.util.Comparator;

/**
 * Text rules of the original Rust contract. Java's own trim/lowercase/length/ordering differ from Rust's for
 * non-ASCII input, and any difference would change decisions, capability bindings or the canonical policy hash.
 */
public final class ContractText {
    /** Rust orders String keys by UTF-8 bytes, which is code point order; String.compareTo uses UTF-16 units. */
    public static final Comparator<String> CODE_POINT_ORDER = ContractText::compareCodePoints;

    private ContractText() {}

    /** Rust char::is_whitespace (Unicode White_Space). Character.isWhitespace skips NBSP and adds U+001C..U+001F. */
    public static boolean isWhitespace(int codePoint) {
        return (codePoint >= 0x09 && codePoint <= 0x0D)
            || codePoint == 0x20
            || codePoint == 0x85
            || codePoint == 0xA0
            || codePoint == 0x1680
            || (codePoint >= 0x2000 && codePoint <= 0x200A)
            || codePoint == 0x2028
            || codePoint == 0x2029
            || codePoint == 0x202F
            || codePoint == 0x205F
            || codePoint == 0x3000;
    }

    public static String trim(String value) {
        int start = 0;
        int end = value.length();
        while (start < end) {
            int codePoint = value.codePointAt(start);
            if (!isWhitespace(codePoint)) break;
            start += Character.charCount(codePoint);
        }
        while (end > start) {
            int codePoint = value.codePointBefore(end);
            if (!isWhitespace(codePoint)) break;
            end -= Character.charCount(codePoint);
        }
        return value.substring(start, end);
    }

    /** Rust str::to_ascii_lowercase: only A-Z change. */
    public static String asciiLowercase(String value) {
        char[] chars = value.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] >= 'A' && chars[i] <= 'Z') chars[i] = (char) (chars[i] + ('a' - 'A'));
        }
        return new String(chars);
    }

    public static String normalized(String value) {
        return asciiLowercase(trim(value));
    }

    /** Rust str::len is the UTF-8 byte length. */
    public static int utf8Length(String value) {
        int bytes = 0;
        for (int i = 0; i < value.length(); ) {
            int codePoint = value.codePointAt(i);
            bytes += codePoint < 0x80 ? 1 : codePoint < 0x800 ? 2 : codePoint < 0x10000 ? 3 : 4;
            i += Character.charCount(codePoint);
        }
        return bytes;
    }

    public static boolean containsWhitespace(String value) {
        return value.codePoints().anyMatch(ContractText::isWhitespace);
    }

    public static boolean isAscii(String value) {
        return value.chars().allMatch(current -> current < 0x80);
    }

    /** Rust strings are valid UTF-8, so JSON escapes producing lone surrogates are rejected there. */
    public static boolean hasUnpairedSurrogate(String value) {
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (Character.isHighSurrogate(current)) {
                if (i + 1 < value.length() && Character.isLowSurrogate(value.charAt(i + 1))) {
                    i++;
                    continue;
                }
                return true;
            }
            if (Character.isLowSurrogate(current)) return true;
        }
        return false;
    }

    private static int compareCodePoints(String left, String right) {
        int i = 0;
        int j = 0;
        while (i < left.length() && j < right.length()) {
            int a = left.codePointAt(i);
            int b = right.codePointAt(j);
            if (a != b) return Integer.compare(a, b);
            i += Character.charCount(a);
            j += Character.charCount(b);
        }
        return Integer.compare(left.length() - i, right.length() - j);
    }
}
