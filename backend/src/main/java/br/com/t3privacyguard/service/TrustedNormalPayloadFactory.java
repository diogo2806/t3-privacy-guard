package br.com.t3privacyguard.service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class TrustedNormalPayloadFactory {
    private static final Set<String> FORBIDDEN_KEYS = Set.of(
        "api_key", "card_number", "credential", "cpf", "password", "private_key", "secret", "ssn", "token"
    );

    private static final Map<String, String> SYNTHETIC_VALUES = Map.ofEntries(
        Map.entry("credential_id", "cred-demo-001"),
        Map.entry("reason", "suspected compromise"),
        Map.entry("employee_department", "finance"),
        Map.entry("account_id", "acct-demo-001"),
        Map.entry("severity", "critical"),
        Map.entry("summary", "synthetic security incident"),
        Map.entry("source", "t3-privacy-guard")
    );

    public Map<String, String> create(List<String> requestedFields) {
        return create("inc-demo-001", requestedFields);
    }

    public Map<String, String> create(String incidentId, List<String> requestedFields) {
        if (incidentId == null || incidentId.isBlank()) throw new IllegalArgumentException("Persisted incident id is required for trusted payload generation");
        LinkedHashMap<String, String> result = new LinkedHashMap<>();
        for (String raw : requestedFields == null ? List.<String>of() : requestedFields) {
            String key = normalizeKey(raw);
            if (key.isEmpty() || FORBIDDEN_KEYS.contains(key) || result.containsKey(key)) continue;
            String value = "incident_id".equals(key) ? incidentId : SYNTHETIC_VALUES.get(key);
            if (value != null) result.put(key, value);
        }
        return Map.copyOf(result);
    }

    static String normalizeKey(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
