package br.com.t3privacyguard.audit;

import br.com.t3privacyguard.domain.AuditIntegrityState;
import br.com.t3privacyguard.persistence.AuditChainHeadEntity;
import br.com.t3privacyguard.persistence.AuditChainHeadRepository;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.privacy.IncidentDataMinimizer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditIntegrityService {
    public static final String INTEGRITY_VERSION = "v1";
    public static final String GENESIS_MAC = "GENESIS";
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private final AuditEventRepository audits;
    private final AuditChainHeadRepository heads;
    private final IncidentRepository incidents;
    private final IncidentDataMinimizer minimizer;
    private final byte[] key;

    public AuditIntegrityService(
        AuditEventRepository audits,
        AuditChainHeadRepository heads,
        IncidentRepository incidents,
        IncidentDataMinimizer minimizer,
        @Value("${privacy-guard.audit-integrity.key}") String integrityKey,
        @Value("${privacy-guard.gateway.service-token:}") String gatewayServiceToken,
        @Value("${privacy-guard.remediation-capability.key:}") String remediationCapabilityKey,
        @Value("${privacy-guard.operator.password:}") String operatorPassword,
        @Value("${T3N_API_KEY:}") String tenantApiKey,
        @Value("${T3N_AGENT_API_KEY:}") String agentApiKey,
        @Value("${SECURITY_API_KEY:}") String securityApiKey
    ) {
        if (integrityKey == null || integrityKey.length() < 32) {
            throw new IllegalStateException("AUDIT_INTEGRITY_KEY must contain at least 32 characters");
        }
        for (String other : List.of(
            nullToEmpty(gatewayServiceToken),
            nullToEmpty(remediationCapabilityKey),
            nullToEmpty(operatorPassword),
            nullToEmpty(tenantApiKey),
            nullToEmpty(agentApiKey),
            nullToEmpty(securityApiKey)
        )) {
            if (!other.isBlank() && integrityKey.equals(other)) {
                throw new IllegalStateException("AUDIT_INTEGRITY_KEY must be different from every other runtime credential");
            }
        }
        this.audits = audits;
        this.heads = heads;
        this.incidents = incidents;
        this.minimizer = minimizer;
        this.key = integrityKey.getBytes(StandardCharsets.UTF_8);
    }

    @Transactional
    public AuditEventEntity append(
        String incidentId,
        String type,
        String message,
        Long t3nSequence,
        String t3nHash,
        String t3nFunction
    ) {
        String normalizedType = boundedRequired(type, 64);
        String sanitizedMessage = minimizer.sanitizeAuditMessage(message);
        AuditChainHeadEntity head = headForAppend(incidentId);
        if (!INTEGRITY_VERSION.equals(head.getIntegrityVersion())) {
            throw new IllegalStateException("Unsupported audit chain integrity version");
        }

        long sequence = head.getLastSequence() + 1;
        String previousMac = sequence == 1 ? GENESIS_MAC : head.getLastMac();
        Instant createdAt = Instant.now();
        String eventMac = calculateMac(key, incidentId, sequence, normalizedType, createdAt, sanitizedMessage, previousMac);
        Long normalizedT3nSequence = t3nSequence != null && t3nSequence >= 0 ? t3nSequence : null;
        String normalizedT3nHash = normalizedT3nSequence == null ? null : bounded(t3nHash, 128);
        String normalizedT3nFunction = bounded(t3nFunction, 120);

        AuditEventEntity event = audits.saveAndFlush(new AuditEventEntity(
            java.util.UUID.randomUUID().toString(),
            incidentId,
            normalizedType,
            sanitizedMessage,
            createdAt,
            normalizedT3nSequence,
            normalizedT3nHash,
            normalizedT3nFunction,
            sequence,
            previousMac,
            eventMac,
            INTEGRITY_VERSION
        ));
        head.advance(sequence, eventMac, INTEGRITY_VERSION);
        heads.save(head);
        return event;
    }

    @Transactional(readOnly = true)
    public AuditIntegrityResult verify(String incidentId, List<AuditEventEntity> events) {
        List<AuditEventEntity> source = events == null ? List.of() : List.copyOf(events);
        boolean hasLegacy = source.stream().anyMatch(this::isLegacy);
        boolean hasPartialIntegrity = source.stream().anyMatch(this::hasPartialIntegrityMetadata);
        List<AuditEventEntity> signed = source.stream()
            .filter(this::hasCompleteIntegrityMetadata)
            .sorted(Comparator.comparingLong(event -> event.getIntegritySequence()))
            .toList();

        if (hasPartialIntegrity) {
            return broken(0, "Audit integrity metadata is incomplete on one or more events.");
        }
        if (signed.isEmpty()) {
            if (hasLegacy) {
                return new AuditIntegrityResult(
                    AuditIntegrityState.LEGACY_UNVERIFIED,
                    0,
                    null,
                    null,
                    "Retained audit events predate the HMAC chain and cannot be called integrity verified."
                );
            }
            return new AuditIntegrityResult(
                AuditIntegrityState.NOT_AVAILABLE,
                0,
                null,
                null,
                "No retained local audit events are available for integrity verification."
            );
        }

        AuditChainHeadEntity persistedHead = heads.findById(incidentId).orElse(null);
        if (persistedHead == null) return broken(0, "Signed audit events exist but the chain head is missing.");
        if (!INTEGRITY_VERSION.equals(persistedHead.getIntegrityVersion())) {
            return broken(0, "The persisted audit chain head uses an unsupported integrity version.");
        }

        String expectedPrevious = GENESIS_MAC;
        long expectedSequence = 1;
        int checked = 0;
        String lastMac = null;
        for (AuditEventEntity event : signed) {
            if (!Objects.equals(event.getIncidentId(), incidentId)) {
                return broken(checked, "An audit event is bound to a different incident.");
            }
            if (!INTEGRITY_VERSION.equals(event.getIntegrityVersion())) {
                return broken(checked, "An audit event uses an unsupported integrity version.");
            }
            if (event.getIntegritySequence() != expectedSequence) {
                return broken(checked, "Audit integrity sequence contains a gap, duplicate or unexpected value.");
            }
            if (!constantTimeEquals(event.getPreviousMac(), expectedPrevious)) {
                return broken(checked, "Audit chain link does not match the previous event MAC.");
            }
            String expectedMac = calculateMac(
                key,
                event.getIncidentId(),
                event.getIntegritySequence(),
                event.getType(),
                event.getCreatedAt(),
                event.getMessage(),
                event.getPreviousMac()
            );
            if (!constantTimeEquals(event.getEventMac(), expectedMac)) {
                return broken(checked, "Audit event MAC does not match the canonical event payload.");
            }
            checked += 1;
            expectedSequence += 1;
            expectedPrevious = event.getEventMac();
            lastMac = event.getEventMac();
        }

        if (persistedHead.getLastSequence() != checked || !constantTimeEquals(persistedHead.getLastMac(), lastMac)) {
            return broken(checked, "Audit chain head does not match the retained signed event tail.");
        }

        if (hasLegacy) {
            return new AuditIntegrityResult(
                AuditIntegrityState.LEGACY_UNVERIFIED,
                checked,
                lastMac,
                INTEGRITY_VERSION,
                "The HMAC-signed tail is valid, but earlier retained events predate integrity signing."
            );
        }
        return new AuditIntegrityResult(
            AuditIntegrityState.VERIFIED,
            checked,
            lastMac,
            INTEGRITY_VERSION,
            "The retained local audit chain was verified with the current HMAC integrity key."
        );
    }

    private AuditChainHeadEntity headForAppend(String incidentId) {
        incidents.findForAuditUpdate(incidentId)
            .orElseThrow(() -> new IllegalStateException("Cannot append audit for a missing incident"));
        AuditChainHeadEntity existing = heads.findForUpdate(incidentId).orElse(null);
        if (existing != null) return existing;
        if (audits.existsByIncidentIdAndIntegritySequenceIsNotNull(incidentId)) {
            throw new IllegalStateException("Audit chain head is missing for existing signed events");
        }
        AuditChainHeadEntity created = new AuditChainHeadEntity(incidentId, 0, GENESIS_MAC, INTEGRITY_VERSION);
        heads.saveAndFlush(created);
        return created;
    }

    private boolean isLegacy(AuditEventEntity event) {
        return event.getIntegritySequence() == null
            && event.getPreviousMac() == null
            && event.getEventMac() == null
            && event.getIntegrityVersion() == null;
    }

    private boolean hasCompleteIntegrityMetadata(AuditEventEntity event) {
        return event.getIntegritySequence() != null
            && event.getPreviousMac() != null
            && event.getEventMac() != null
            && event.getIntegrityVersion() != null;
    }

    private boolean hasPartialIntegrityMetadata(AuditEventEntity event) {
        return !isLegacy(event) && !hasCompleteIntegrityMetadata(event);
    }

    static String canonicalPayload(
        String incidentId,
        long sequence,
        String type,
        Instant createdAt,
        String message,
        String previousMac
    ) {
        return String.join("\n",
            INTEGRITY_VERSION,
            incidentId,
            Long.toString(sequence),
            type,
            createdAt.toString(),
            message,
            previousMac
        );
    }

    static String calculateMac(
        byte[] key,
        String incidentId,
        long sequence,
        String type,
        Instant createdAt,
        String message,
        String previousMac
    ) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            byte[] value = mac.doFinal(canonicalPayload(incidentId, sequence, type, createdAt, message, previousMac).getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(value);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("HMAC-SHA-256 is unavailable", ex);
        }
    }

    private static boolean constantTimeEquals(String actual, String expected) {
        if (actual == null || expected == null) return false;
        return MessageDigest.isEqual(actual.getBytes(StandardCharsets.US_ASCII), expected.getBytes(StandardCharsets.US_ASCII));
    }

    private static String bounded(String value, int max) {
        if (value == null || value.isBlank()) return null;
        String normalized = value.trim();
        return normalized.substring(0, Math.min(normalized.length(), max));
    }

    private static String boundedRequired(String value, int max) {
        String normalized = bounded(value, max);
        if (normalized == null) throw new IllegalArgumentException("Audit event type is required");
        return normalized;
    }

    private static String nullToEmpty(String value) { return value == null ? "" : value; }

    private static AuditIntegrityResult broken(int checked, String message) {
        return new AuditIntegrityResult(AuditIntegrityState.BROKEN, checked, null, INTEGRITY_VERSION, message);
    }

    public record AuditIntegrityResult(
        AuditIntegrityState state,
        int eventsChecked,
        String head,
        String version,
        String message
    ) {}
}
