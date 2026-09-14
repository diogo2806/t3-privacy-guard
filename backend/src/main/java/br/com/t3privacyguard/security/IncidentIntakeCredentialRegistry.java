package br.com.t3privacyguard.security;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class IncidentIntakeCredentialRegistry {
    private static final Pattern INTEGRATION_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,63}");
    private static final Pattern DISPLAY_NAME = Pattern.compile("[A-Za-z0-9][A-Za-z0-9 ._/-]{0,47}");
    private static final int MIN_TOKEN_LENGTH = 32;
    private static final int MAX_TOKEN_LENGTH = 512;
    private static final long MAX_CREDENTIAL_FILE_BYTES = 64 * 1024L;

    private final boolean enabled;
    private final List<Credential> staticCredentials;
    private final Path credentialsFile;
    private final ObjectMapper mapper;

    public IncidentIntakeCredentialRegistry(
        @Value("${privacy-guard.incident-intake.enabled:false}") boolean enabled,
        @Value("${privacy-guard.incident-intake.integrations-json:[]}") String integrationsJson,
        @Value("${privacy-guard.incident-intake.credentials-file:}") String credentialsFile,
        ObjectMapper mapper
    ) {
        this.enabled = enabled;
        this.mapper = mapper;
        this.credentialsFile = normalizeFile(credentialsFile);

        String staticJson = integrationsJson == null || integrationsJson.isBlank() ? "[]" : integrationsJson.trim();
        if (this.credentialsFile != null && !"[]".equals(staticJson)) {
            throw new IllegalStateException("Configure incident intake credentials from JSON or a runtime file, not both");
        }

        if (!enabled) {
            this.staticCredentials = List.of();
            return;
        }

        if (this.credentialsFile != null) {
            this.staticCredentials = List.of();
            requireRuntimeFileCredentials();
        } else {
            this.staticCredentials = parse(staticJson, mapper);
            if (staticCredentials.isEmpty()) {
                throw new IllegalStateException("Incident intake is enabled but no integration credentials are configured");
            }
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public Optional<IncidentIntakePrincipal> authenticate(String bearerToken) {
        if (!enabled || bearerToken == null || bearerToken.length() < MIN_TOKEN_LENGTH || bearerToken.length() > MAX_TOKEN_LENGTH) {
            return Optional.empty();
        }
        List<Credential> activeCredentials = credentialsFile == null ? staticCredentials : readRuntimeFileCredentials();
        if (activeCredentials.isEmpty()) return Optional.empty();

        byte[] candidate = bearerToken.getBytes(StandardCharsets.UTF_8);
        for (Credential credential : activeCredentials) {
            if (MessageDigest.isEqual(candidate, credential.tokenBytes())) {
                return Optional.of(new IncidentIntakePrincipal(credential.id(), credential.displayName()));
            }
        }
        return Optional.empty();
    }

    private void requireRuntimeFileCredentials() {
        List<Credential> loaded = readRuntimeFileCredentials();
        if (loaded.isEmpty()) {
            throw new IllegalStateException("Incident intake credential file must exist, be valid and contain at least one integration");
        }
    }

    private List<Credential> readRuntimeFileCredentials() {
        try {
            if (!Files.isRegularFile(credentialsFile)) return List.of();
            long size = Files.size(credentialsFile);
            if (size <= 0 || size > MAX_CREDENTIAL_FILE_BYTES) return List.of();
            return parse(Files.readString(credentialsFile, StandardCharsets.UTF_8), mapper);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private static Path normalizeFile(String value) {
        if (value == null || value.isBlank()) return null;
        return Path.of(value.trim()).toAbsolutePath().normalize();
    }

    private static List<Credential> parse(String raw, ObjectMapper mapper) {
        List<ConfiguredIntegration> configured;
        try {
            configured = mapper.readValue(raw == null || raw.isBlank() ? "[]" : raw, new TypeReference<List<ConfiguredIntegration>>() {});
        } catch (Exception ex) {
            throw new IllegalStateException("Incident intake credentials JSON is invalid", ex);
        }

        Set<String> ids = new HashSet<>();
        Set<String> tokenFingerprints = new HashSet<>();
        List<Credential> result = new ArrayList<>(configured.size());
        for (ConfiguredIntegration integration : configured) {
            String id = require(integration.id(), "integration id");
            String displayName = require(integration.name(), "integration display name");
            String token = require(integration.token(), "integration token");
            if (!INTEGRATION_ID.matcher(id).matches()) {
                throw new IllegalStateException("Incident intake integration id must use safe opaque characters and be at most 64 characters");
            }
            if (!DISPLAY_NAME.matcher(displayName).matches()) {
                throw new IllegalStateException("Incident intake integration display name contains unsupported characters or is too long");
            }
            if (token.length() < MIN_TOKEN_LENGTH || token.length() > MAX_TOKEN_LENGTH) {
                throw new IllegalStateException("Incident intake integration token must contain between 32 and 512 characters");
            }
            RuntimeSecretPolicy.rejectDocumentationPlaceholder(token, "incident intake token");
            if (!ids.add(id)) throw new IllegalStateException("Incident intake integration ids must be unique");

            String tokenFingerprint = java.util.HexFormat.of().formatHex(sha256(token));
            if (!tokenFingerprints.add(tokenFingerprint)) {
                throw new IllegalStateException("Incident intake integration tokens must be unique");
            }
            result.add(new Credential(id, displayName, token.getBytes(StandardCharsets.UTF_8)));
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
        if (value == null || value.isBlank()) throw new IllegalStateException("Incident intake " + label + " is required");
        return value.trim();
    }

    private record Credential(String id, String displayName, byte[] tokenBytes) {
        private Credential {
            tokenBytes = tokenBytes.clone();
        }

        @Override
        public byte[] tokenBytes() {
            return tokenBytes.clone();
        }
    }

    private record ConfiguredIntegration(String id, String name, String token) {}
}
