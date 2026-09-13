package br.com.t3privacyguard.privacy;

import java.text.Normalizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class IncidentDataMinimizer {
    static final int MAX_TITLE_LENGTH = 120;
    static final int MAX_SUMMARY_LENGTH = 800;
    static final int MAX_SOURCE_LENGTH = 80;
    private static final int MAX_AUDIT_LENGTH = 600;

    private static final Pattern EMAIL = Pattern.compile("\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,63}\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern CPF = Pattern.compile("(?<!\\d)\\d{3}\\.?\\d{3}\\.?\\d{3}-?\\d{2}(?!\\d)");
    private static final Pattern BEARER = Pattern.compile("\\bAuthorization\\s*:\\s*Bearer\\s+[A-Za-z0-9._~+/\\-]{8,}={0,2}", Pattern.CASE_INSENSITIVE);
    private static final Pattern JWT = Pattern.compile("\\beyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\b");
    private static final Pattern PRIVATE_KEY = Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\\b0x[a-fA-F0-9]{64}\\b");
    private static final Pattern PASSWORD = Pattern.compile("\\bpassword\\s*[:=]\\s*(?:\"[^\"]{4,}\"|'[^']{4,}'|[^\\s,;]{4,})", Pattern.CASE_INSENSITIVE);
    private static final Pattern API_KEY = Pattern.compile(
        "\\b(?:api[_-]?key|access[_-]?token|secret[_-]?key|token)\\s*[:=]\\s*(?:\"[^\"]{6,}\"|'[^']{6,}'|[A-Za-z0-9._~+/\\-]{8,}={0,2})|\\bsk-[A-Za-z0-9_-]{16,}\\b",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern CARD = Pattern.compile("(?<!\\d)(?:\\d[ -]?){12,18}\\d(?!\\d)");

    public MinimizedIncident minimize(String title, String summary, String source) {
        String normalizedTitle = normalize(title);
        String normalizedSummary = normalize(summary);
        String normalizedSource = normalize(source);
        if (normalizedTitle.isBlank() || normalizedSummary.isBlank() || normalizedSource.isBlank()) {
            throw new IllegalArgumentException("Incident title, summary and source are required");
        }

        String candidate = normalizedTitle + "\n" + normalizedSummary + "\n" + normalizedSource;
        if (containsSensitiveLiteral(candidate)) {
            throw new UnsafeIncidentContentException();
        }

        return new MinimizedIncident(
            limit(normalizedTitle, MAX_TITLE_LENGTH),
            limit(normalizedSummary, MAX_SUMMARY_LENGTH),
            limit(normalizedSource, MAX_SOURCE_LENGTH)
        );
    }

    public String sanitizeAuditMessage(String message) {
        String normalized = normalize(message);
        if (containsSensitiveLiteral(normalized)) {
            return "Sensitive details were omitted from this audit event.";
        }
        return limit(normalized, MAX_AUDIT_LENGTH);
    }

    boolean containsSensitiveLiteral(String value) {
        String normalized = normalize(value);
        return EMAIL.matcher(normalized).find()
            || containsValidCpf(normalized)
            || BEARER.matcher(normalized).find()
            || JWT.matcher(normalized).find()
            || PRIVATE_KEY.matcher(normalized).find()
            || PASSWORD.matcher(normalized).find()
            || API_KEY.matcher(normalized).find()
            || containsLuhnCard(normalized);
    }

    private static boolean containsValidCpf(String value) {
        Matcher matcher = CPF.matcher(value);
        while (matcher.find()) {
            if (validCpf(matcher.group())) return true;
        }
        return false;
    }

    private static boolean validCpf(String value) {
        String digits = value.replaceAll("\\D", "");
        if (digits.length() != 11 || digits.chars().distinct().count() == 1) return false;
        return cpfDigit(digits, 9) == Character.digit(digits.charAt(9), 10)
            && cpfDigit(digits, 10) == Character.digit(digits.charAt(10), 10);
    }

    private static int cpfDigit(String digits, int length) {
        int sum = 0;
        for (int index = 0; index < length; index++) {
            sum += Character.digit(digits.charAt(index), 10) * (length + 1 - index);
        }
        int remainder = (sum * 10) % 11;
        return remainder == 10 ? 0 : remainder;
    }

    private static boolean containsLuhnCard(String value) {
        Matcher matcher = CARD.matcher(value);
        while (matcher.find()) {
            if (passesLuhn(matcher.group())) return true;
        }
        return false;
    }

    private static boolean passesLuhn(String value) {
        String digits = value.replaceAll("\\D", "");
        if (digits.length() < 13 || digits.length() > 19) return false;
        int sum = 0;
        boolean doubleDigit = false;
        for (int index = digits.length() - 1; index >= 0; index--) {
            int digit = Character.digit(digits.charAt(index), 10);
            if (doubleDigit) {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }
            sum += digit;
            doubleDigit = !doubleDigit;
        }
        return sum % 10 == 0;
    }

    private static String normalize(String value) {
        if (value == null) return "";
        return Normalizer.normalize(value, Normalizer.Form.NFKC).trim().replaceAll("\\s+", " ");
    }

    private static String limit(String value, int maxLength) {
        return value.substring(0, Math.min(value.length(), maxLength));
    }

    public record MinimizedIncident(String title, String summary, String source) {}
}
