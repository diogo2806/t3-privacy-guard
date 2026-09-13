package br.com.t3privacyguard.privacy;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.Normalizer;
import java.util.Locale;
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
    private static final Pattern CNPJ = Pattern.compile("(?<!\\d)\\d{2}\\.?\\d{3}\\.?\\d{3}\\/?\\d{4}-?\\d{2}(?!\\d)");
    private static final Pattern E164_PHONE = Pattern.compile("(?<![\\w+])\\+[1-9]\\d{7,14}(?!\\d)");
    private static final Pattern LABELED_PHONE = Pattern.compile(
        "\\b(?:phone|mobile|telefone|celular)\\s*[:=]\\s*(\\+?\\d[\\d(). -]{6,}\\d)",
        Pattern.CASE_INSENSITIVE
    );
    private static final Pattern LABELED_IP = Pattern.compile(
        "\\b(?:(?:client|customer|user)\\s+ip(?:\\s+address)?|ip\\s+(?:do|da)\\s+(?:cliente|usu[aá]rio))\\s*[:=]\\s*(\\[[0-9a-f:.]+\\]|[0-9a-f:.]+)",
        Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE
    );
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
            || containsValidCnpj(normalized)
            || containsStrongPhoneLiteral(normalized)
            || containsLabeledPublicIp(normalized)
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

    private static boolean containsValidCnpj(String value) {
        Matcher matcher = CNPJ.matcher(value);
        while (matcher.find()) {
            if (validCnpj(matcher.group())) return true;
        }
        return false;
    }

    private static boolean validCnpj(String value) {
        String digits = value.replaceAll("\\D", "");
        if (digits.length() != 14 || digits.chars().distinct().count() == 1) return false;
        return cnpjDigit(digits, 12) == Character.digit(digits.charAt(12), 10)
            && cnpjDigit(digits, 13) == Character.digit(digits.charAt(13), 10);
    }

    private static int cnpjDigit(String digits, int length) {
        int[] firstWeights = {5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
        int[] secondWeights = {6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2};
        int[] weights = length == 12 ? firstWeights : secondWeights;
        int sum = 0;
        for (int index = 0; index < weights.length; index++) {
            sum += Character.digit(digits.charAt(index), 10) * weights[index];
        }
        int remainder = sum % 11;
        return remainder < 2 ? 0 : 11 - remainder;
    }

    private static boolean containsStrongPhoneLiteral(String value) {
        if (E164_PHONE.matcher(value).find()) return true;
        Matcher matcher = LABELED_PHONE.matcher(value);
        while (matcher.find()) {
            long digits = matcher.group(1).chars().filter(Character::isDigit).count();
            if (digits >= 8 && digits <= 15) return true;
        }
        return false;
    }

    private static boolean containsLabeledPublicIp(String value) {
        Matcher matcher = LABELED_IP.matcher(value);
        while (matcher.find()) {
            if (isPublicIpAddress(matcher.group(1))) return true;
        }
        return false;
    }

    private static boolean isPublicIpAddress(String value) {
        String candidate = value.trim().replaceFirst("^\\[", "").replaceFirst("\\]?[.,;)]*$", "");
        if (candidate.contains(".")) return isPublicIpv4(candidate);
        if (!candidate.contains(":")) return false;
        try {
            InetAddress address = InetAddress.getByName(candidate);
            if (!(address instanceof Inet6Address)) return false;
            String normalized = candidate.toLowerCase(Locale.ROOT);
            if (normalized.equals("::") || normalized.equals("::1")) return false;
            if (normalized.startsWith("fc") || normalized.startsWith("fd")) return false;
            if (normalized.matches("^fe[89ab].*")) return false;
            if (normalized.startsWith("ff")) return false;
            if (normalized.startsWith("2001:db8:") || normalized.equals("2001:db8::")) return false;
            if (normalized.startsWith("::ffff:")) return false;
            return !address.isAnyLocalAddress()
                && !address.isLoopbackAddress()
                && !address.isLinkLocalAddress()
                && !address.isSiteLocalAddress()
                && !address.isMulticastAddress();
        } catch (UnknownHostException ignored) {
            return false;
        }
    }

    private static boolean isPublicIpv4(String candidate) {
        String[] parts = candidate.split("\\.", -1);
        if (parts.length != 4) return false;
        int[] octets = new int[4];
        for (int index = 0; index < parts.length; index++) {
            if (parts[index].isBlank() || parts[index].length() > 3) return false;
            try {
                octets[index] = Integer.parseInt(parts[index]);
            } catch (NumberFormatException ignored) {
                return false;
            }
            if (octets[index] < 0 || octets[index] > 255) return false;
        }

        int first = octets[0];
        int second = octets[1];
        int third = octets[2];
        if (first == 0 || first == 10 || first == 127 || first >= 224) return false;
        if (first == 100 && second >= 64 && second <= 127) return false;
        if (first == 169 && second == 254) return false;
        if (first == 172 && second >= 16 && second <= 31) return false;
        if (first == 192 && second == 168) return false;
        if (first == 192 && second == 0) return false;
        if (first == 198 && (second == 18 || second == 19)) return false;
        if (first == 198 && second == 51 && third == 100) return false;
        if (first == 203 && second == 0 && third == 113) return false;
        return true;
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
