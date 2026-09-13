package br.com.t3privacyguard.audit;

import br.com.t3privacyguard.persistence.AuditChainHeadEntity;
import br.com.t3privacyguard.persistence.AuditChainHeadRepository;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.service.IncidentNotFoundException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditIntegrityService {
    private final IncidentRepository incidents;
    private final AuditEventRepository audits;
    private final AuditChainHeadRepository heads;
    private final AuditIntegrityKeyring keyring;
    private final boolean allowLegacyBootstrap;

    public AuditIntegrityService(
        IncidentRepository incidents,
        AuditEventRepository audits,
        AuditChainHeadRepository heads,
        AuditIntegrityKeyring keyring,
        @Value("${privacy-guard.audit-integrity.allow-legacy-bootstrap:false}") boolean allowLegacyBootstrap
    ) {
        this.incidents = incidents;
        this.audits = audits;
        this.heads = heads;
        this.keyring = keyring;
        this.allowLegacyBootstrap = allowLegacyBootstrap;
    }

    @Transactional
    public AuditEventEntity append(String incidentId, String type, String message) {
        return append(incidentId, type, message, null, null, null);
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
        incidents.findByIdForUpdate(incidentId)
            .orElseThrow(() -> new IncidentNotFoundException("Incident not found"));

        List<AuditEventEntity> existing = audits.findByIncidentIdOrderByCreatedAtAscIdAsc(incidentId);
        Optional<AuditChainHeadEntity> existingHead = heads.findById(incidentId);

        long sequence;
        long legacyCount;
        String previousMac;

        if (existingHead.isPresent()) {
            Verification verification = verifyChain(incidentId, existing, existingHead.get());
            if (!isAppendableProtectedChain(verification.state())) {
                throw new AuditIntegrityException("Local audit integrity is not verifiable; refusing to append or repair history automatically");
            }
            sequence = existingHead.get().getLastSequence() + 1;
            legacyCount = existingHead.get().getLegacyEventCount();
            previousMac = existingHead.get().getLastEventMac();
        } else {
            if (existing.stream().anyMatch(this::hasAnyIntegrityMetadata)) {
                throw new AuditIntegrityException("Authenticated audit events exist without their chain head");
            }
            if (!existing.isEmpty() && !allowLegacyBootstrap) {
                throw new AuditIntegrityException("Legacy audit bootstrap is disabled; refusing to create a new trust root for pre-existing history automatically");
            }
            sequence = 1;
            legacyCount = existing.size();
            previousMac = AuditMac.GENESIS;
        }

        Instant createdAt = nextTimestamp(existing);
        String keyId = keyring.currentKeyId();
        String eventId = UUID.randomUUID().toString();
        String eventMac = AuditMac.hmacHex(
            keyring.currentKey(),
            AuditMac.canonicalEvent(
                keyId,
                incidentId,
                eventId,
                sequence,
                type,
                createdAt,
                message,
                t3nSequence,
                t3nHash,
                t3nFunction,
                previousMac
            )
        );

        AuditEventEntity event = audits.saveAndFlush(new AuditEventEntity(
            eventId,
            incidentId,
            type,
            message,
            createdAt,
            t3nSequence,
            t3nHash,
            t3nFunction,
            sequence,
            previousMac,
            eventMac,
            AuditMac.VERSION,
            keyId
        ));

        String headMac = AuditMac.hmacHex(
            keyring.currentKey(),
            AuditMac.canonicalHead(keyId, incidentId, sequence, eventMac, legacyCount, createdAt)
        );
        AuditChainHeadEntity head = existingHead.orElseGet(() -> new AuditChainHeadEntity(
            incidentId,
            sequence,
            eventMac,
            AuditMac.VERSION,
            keyId,
            legacyCount,
            headMac,
            createdAt
        ));
        if (existingHead.isPresent()) {
            head.advance(sequence, eventMac, AuditMac.VERSION, keyId, legacyCount, headMac, createdAt);
        }
        heads.saveAndFlush(head);
        return event;
    }

    @Transactional(readOnly = true)
    public Verification verify(String incidentId) {
        List<AuditEventEntity> events = audits.findByIncidentIdOrderByCreatedAtAscIdAsc(incidentId);
        Optional<AuditChainHeadEntity> head = heads.findById(incidentId);

        if (events.isEmpty()) {
            return broken(
                events,
                0,
                head.map(AuditChainHeadEntity::getLastEventMac).orElse(null),
                head.isPresent()
                    ? "The authenticated chain head exists but audit events are missing."
                    : "No local audit events are available for an active incident."
            );
        }

        if (head.isEmpty()) {
            if (events.stream().allMatch(this::isLegacy)) {
                return new Verification(
                    AuditIntegrityState.LEGACY_UNVERIFIED,
                    0,
                    null,
                    "legacy",
                    "These events predate local HMAC integrity protection and cannot be retroactively authenticated.",
                    List.copyOf(events)
                );
            }
            return broken(events, 0, null, "Authenticated audit metadata exists without its chain head.");
        }

        return verifyChain(incidentId, events, head.get());
    }

    @Transactional(readOnly = true)
    public void assertAppendable(String incidentId) {
        Verification verification = verify(incidentId);
        boolean trustedForProtectedChange = verification.state() == AuditIntegrityState.VERIFIED
            || (verification.state() == AuditIntegrityState.LEGACY_UNVERIFIED && verification.head() != null);
        if (!trustedForProtectedChange) {
            throw new AuditIntegrityException("Local audit integrity check failed; protected execution is blocked until investigated");
        }
    }

    private Verification verifyChain(String incidentId, List<AuditEventEntity> events, AuditChainHeadEntity head) {
        if (!AuditMac.VERSION.equals(head.getIntegrityVersion())) {
            return broken(events, 0, head.getLastEventMac(), "Unsupported or modified audit chain-head version.");
        }

        Optional<byte[]> headKey = keyring.resolve(head.getIntegrityKeyId());
        if (headKey.isEmpty()) {
            return keyMismatch(events, 0, head.getLastEventMac(), "The key version required to verify the chain head is not configured.");
        }

        String expectedHeadMac = AuditMac.hmacHex(
            headKey.get(),
            AuditMac.canonicalHead(
                head.getIntegrityKeyId(),
                incidentId,
                head.getLastSequence(),
                head.getLastEventMac(),
                head.getLegacyEventCount(),
                head.getUpdatedAt()
            )
        );
        if (!AuditMac.secureHexEquals(head.getHeadMac(), expectedHeadMac)) {
            return broken(events, 0, head.getLastEventMac(), "The authenticated audit chain head does not match its stored metadata.");
        }

        int secureStart = 0;
        while (secureStart < events.size() && isLegacy(events.get(secureStart))) secureStart++;
        for (int index = secureStart; index < events.size(); index++) {
            if (!hasCompleteIntegrityMetadata(events.get(index))) {
                return broken(events, 0, head.getLastEventMac(), "Audit integrity metadata is partial, missing or appears after authenticated events began.");
            }
        }

        if (head.getLegacyEventCount() != secureStart) {
            return broken(events, 0, head.getLastEventMac(), "The legacy audit-event count no longer matches the authenticated chain head.");
        }

        List<AuditEventEntity> protectedEvents = events.subList(secureStart, events.size());
        if (protectedEvents.isEmpty()) {
            return broken(events, 0, head.getLastEventMac(), "The authenticated chain head points to events that are no longer present.");
        }

        long expectedSequence = 1;
        String expectedPreviousMac = AuditMac.GENESIS;
        int checked = 0;

        for (AuditEventEntity event : protectedEvents) {
            if (event.getSequence() == null || event.getSequence() != expectedSequence) {
                return broken(events, checked, head.getLastEventMac(), "Audit sequence contains a gap, duplicate or reordering.");
            }
            if (!AuditMac.VERSION.equals(event.getIntegrityVersion())) {
                return broken(events, checked, head.getLastEventMac(), "An audit event has an unsupported or modified integrity version.");
            }
            if (!AuditMac.secureHexEquals(event.getPreviousMac(), expectedPreviousMac)) {
                return broken(events, checked, head.getLastEventMac(), "An audit event no longer links to the preceding authenticated event.");
            }

            Optional<byte[]> eventKey = keyring.resolve(event.getIntegrityKeyId());
            if (eventKey.isEmpty()) {
                return keyMismatch(events, checked, head.getLastEventMac(), "The key version required to verify an audit event is not configured.");
            }

            String expectedEventMac = AuditMac.hmacHex(
                eventKey.get(),
                AuditMac.canonicalEvent(
                    event.getIntegrityKeyId(),
                    incidentId,
                    event.getId(),
                    event.getSequence(),
                    event.getType(),
                    event.getCreatedAt(),
                    event.getMessage(),
                    event.getT3nSequence(),
                    event.getT3nHash(),
                    event.getT3nFunction(),
                    event.getPreviousMac()
                )
            );
            if (!AuditMac.secureHexEquals(event.getEventMac(), expectedEventMac)) {
                return broken(events, checked, head.getLastEventMac(), "An audit event MAC does not match its persisted content or T3N provenance metadata.");
            }

            expectedPreviousMac = event.getEventMac();
            expectedSequence++;
            checked++;
        }

        if (head.getLastSequence() != checked || !AuditMac.secureHexEquals(head.getLastEventMac(), expectedPreviousMac)) {
            return broken(events, checked, head.getLastEventMac(), "The authenticated chain head does not match the final audit event.");
        }

        AuditIntegrityState state = secureStart == 0 ? AuditIntegrityState.VERIFIED : AuditIntegrityState.LEGACY_UNVERIFIED;
        String detail = secureStart == 0
            ? "HMAC chain, sequence and authenticated head verified with configured key versions."
            : "Authenticated events verify, but the legacy prefix predates HMAC protection and remains explicitly unverified.";
        return new Verification(state, checked, head.getLastEventMac(), AuditMac.VERSION, detail, List.copyOf(events));
    }

    private Instant nextTimestamp(List<AuditEventEntity> existing) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        if (existing.isEmpty()) return now;
        Instant last = existing.get(existing.size() - 1).getCreatedAt();
        return now.isAfter(last) ? now : last.plusMillis(1);
    }

    private boolean isLegacy(AuditEventEntity event) { return !hasAnyIntegrityMetadata(event); }

    private boolean hasAnyIntegrityMetadata(AuditEventEntity event) {
        return event.getSequence() != null
            || event.getPreviousMac() != null
            || event.getEventMac() != null
            || event.getIntegrityVersion() != null
            || event.getIntegrityKeyId() != null;
    }

    private boolean hasCompleteIntegrityMetadata(AuditEventEntity event) {
        return event.getSequence() != null
            && event.getPreviousMac() != null
            && event.getEventMac() != null
            && event.getIntegrityVersion() != null
            && event.getIntegrityKeyId() != null;
    }

    private static boolean isAppendableProtectedChain(AuditIntegrityState state) {
        return state == AuditIntegrityState.VERIFIED || state == AuditIntegrityState.LEGACY_UNVERIFIED;
    }

    private Verification broken(List<AuditEventEntity> events, int checked, String head, String detail) {
        return new Verification(AuditIntegrityState.BROKEN, checked, head, AuditMac.VERSION, detail, List.copyOf(events));
    }

    private Verification keyMismatch(List<AuditEventEntity> events, int checked, String head, String detail) {
        return new Verification(AuditIntegrityState.KEY_MISMATCH, checked, head, AuditMac.VERSION, detail, List.copyOf(events));
    }

    public record Verification(
        AuditIntegrityState state,
        int eventsChecked,
        String head,
        String version,
        String detail,
        List<AuditEventEntity> events
    ) {}
}
