package br.com.t3privacyguard.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Turns the identity provider's group or role claim into Privacy Guard roles. Only the configured mapping grants a
 * role: an account whose claim matches nothing gets no role and cannot sign in.
 */
public final class SsoRoleMapper {
    static final Set<String> ROLES = Set.of("ANALYST", "APPROVER", "EXECUTOR", "AUDITOR", "POLICY_ADMIN");

    private final List<String> claimPath;
    private final Map<String, Set<String>> valuesByRole;

    public SsoRoleMapper(String rolesClaim, String roleMappingJson, ObjectMapper mapper) {
        if (rolesClaim == null || rolesClaim.isBlank()) throw new IllegalStateException("OIDC_ROLES_CLAIM is required for single sign-on");
        this.claimPath = List.of(rolesClaim.trim().split("\\."));
        Map<String, List<String>> parsed;
        try {
            parsed = mapper.readValue(roleMappingJson == null || roleMappingJson.isBlank() ? "{}" : roleMappingJson, new TypeReference<>() {});
        } catch (Exception ex) {
            throw new IllegalStateException("OIDC_ROLE_MAPPING must be a JSON object from role to a list of claim values");
        }
        Map<String, Set<String>> mapping = new LinkedHashMap<>();
        parsed.forEach((role, values) -> {
            if (!ROLES.contains(role)) throw new IllegalStateException("OIDC_ROLE_MAPPING names an unknown role: " + role);
            if (values == null || values.isEmpty() || values.stream().anyMatch(value -> value == null || value.isBlank())) {
                throw new IllegalStateException("OIDC_ROLE_MAPPING must list at least one claim value for " + role);
            }
            mapping.put(role, Set.copyOf(values.stream().map(String::trim).toList()));
        });
        if (mapping.isEmpty()) throw new IllegalStateException("OIDC_ROLE_MAPPING must grant at least one role");
        this.valuesByRole = Map.copyOf(mapping);
    }

    public Set<GrantedAuthority> authorities(Map<String, Object> claims) {
        Set<String> values = claimValues(claims);
        Set<String> roles = new TreeSet<>();
        valuesByRole.forEach((role, granting) -> {
            if (granting.stream().anyMatch(values::contains)) roles.add(role);
        });
        Set<GrantedAuthority> authorities = new java.util.LinkedHashSet<>();
        roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
        return authorities;
    }

    /** A list claim, or a string with values separated by spaces or commas (some providers send scopes that way). */
    private Set<String> claimValues(Map<String, Object> claims) {
        Object current = claims;
        for (String segment : claimPath) {
            if (!(current instanceof Map<?, ?> map)) return Set.of();
            current = map.get(segment);
        }
        Set<String> values = new TreeSet<>();
        if (current instanceof Collection<?> collection) {
            collection.stream().filter(String.class::isInstance).map(value -> ((String) value).trim()).forEach(values::add);
        } else if (current instanceof String text) {
            for (String value : text.split("[\\s,]+")) if (!value.isBlank()) values.add(value);
        }
        return values;
    }
}
