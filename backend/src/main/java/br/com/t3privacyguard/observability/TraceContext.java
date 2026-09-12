package br.com.t3privacyguard.observability;

import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.MDC;

public final class TraceContext {
    public static final String HEADER = "X-Trace-Id";
    public static final String MDC_KEY = "traceId";
    private static final Pattern SAFE_TRACE_ID = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$");

    private TraceContext() {}

    public static String sanitizeOrGenerate(String candidate) {
        if (candidate != null) {
            String normalized = candidate.trim();
            if (SAFE_TRACE_ID.matcher(normalized).matches()) return normalized;
        }
        return UUID.randomUUID().toString();
    }

    public static String currentOrGenerate() {
        String current = MDC.get(MDC_KEY);
        return current == null || current.isBlank() ? UUID.randomUUID().toString() : current;
    }
}
