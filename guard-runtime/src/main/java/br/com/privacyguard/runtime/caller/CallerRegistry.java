package br.com.privacyguard.runtime.caller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Replaces T3N identities and function-scoped delegation: each caller has its own bearer token and an explicit list
 * of functions. Unknown callers get 401 and ungranted functions 403 before any policy code runs.
 */
@Component
public class CallerRegistry {
    private static final Pattern CALLER_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}");
    private static final int MIN_TOKEN_LENGTH = 32;
    private static final int MAX_TOKEN_LENGTH = 512;

    private final List<Credential> credentials;

    public CallerRegistry(@Value("${guard-runtime.callers-json:[]}") String callersJson, ObjectMapper mapper) {
        this.credentials = parse(callersJson, mapper);
        if (credentials.isEmpty()) throw new IllegalStateException("guard-runtime needs at least one caller in guard-runtime.callers-json");
    }

    public Optional<Caller> authenticate(String bearerToken) {
        if (bearerToken == null || bearerToken.length() < MIN_TOKEN_LENGTH || bearerToken.length() > MAX_TOKEN_LENGTH) {
            return Optional.empty();
        }
        byte[] candidate = bearerToken.getBytes(StandardCharsets.UTF_8);
        for (Credential credential : credentials) {
            if (MessageDigest.isEqual(candidate, credential.tokenBytes())) return Optional.of(credential.caller());
        }
        return Optional.empty();
    }

    /**
     * Whether the id belongs to a configured caller allowed to propose (evaluate-action). Used when remediation
     * re-evaluates the policy for the agent that proposed the action; the contract accepted any did:t3n: there.
     */
    public boolean isProposalAgent(String id) {
        return credentials.stream().anyMatch(credential -> credential.caller().hasId(id) && credential.caller().mayCall(GuardFunction.EVALUATE_ACTION));
    }

    private static List<Credential> parse(String raw, ObjectMapper mapper) {
        List<ConfiguredCaller> configured;
        try {
            configured = mapper.readValue(raw == null || raw.isBlank() ? "[]" : raw, new TypeReference<List<ConfiguredCaller>>() {});
        } catch (Exception ex) {
            throw new IllegalStateException("guard-runtime callers JSON is invalid", ex);
        }

        Set<String> ids = new HashSet<>();
        Set<String> tokenFingerprints = new HashSet<>();
        List<Credential> result = new ArrayList<>(configured.size());
        for (ConfiguredCaller entry : configured) {
            String id = require(entry.id(), "caller id");
            String token = require(entry.token(), "caller token");
            if (!CALLER_ID.matcher(id).matches()) {
                throw new IllegalStateException("guard-runtime caller id must use safe opaque characters and be at most 128 characters");
            }
            if (token.length() < MIN_TOKEN_LENGTH || token.length() > MAX_TOKEN_LENGTH) {
                throw new IllegalStateException("guard-runtime caller token must contain between 32 and 512 characters");
            }
            if (entry.functions() == null || entry.functions().isEmpty()) {
                throw new IllegalStateException("guard-runtime caller " + id + " must be granted at least one function");
            }
            EnumSet<GuardFunction> functions = EnumSet.noneOf(GuardFunction.class);
            for (String name : entry.functions()) {
                functions.add(GuardFunction.fromWireName(name)
                    .orElseThrow(() -> new IllegalStateException("guard-runtime caller " + id + " references an unknown function")));
            }
            if (!ids.add(id)) throw new IllegalStateException("guard-runtime caller ids must be unique");
            if (!tokenFingerprints.add(HexFormat.of().formatHex(sha256(token)))) {
                throw new IllegalStateException("guard-runtime caller tokens must be unique");
            }
            result.add(new Credential(new Caller(id, functions), token.getBytes(StandardCharsets.UTF_8)));
        }
        return List.copyOf(result);
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private static String require(String value, String label) {
        if (value == null || value.isBlank()) throw new IllegalStateException("guard-runtime " + label + " is required");
        return value.trim();
    }

    private record Credential(Caller caller, byte[] tokenBytes) {
        private Credential {
            tokenBytes = tokenBytes.clone();
        }

        @Override
        public byte[] tokenBytes() {
            return tokenBytes.clone();
        }
    }

    private record ConfiguredCaller(String id, String token, List<String> functions) {}
}
