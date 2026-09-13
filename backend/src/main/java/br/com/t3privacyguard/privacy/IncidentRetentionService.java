package br.com.t3privacyguard.privacy;

import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.persistence.AuditEventRepository;
import br.com.t3privacyguard.persistence.ExecutionTraceEventRepository;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.persistence.PolicyDecisionRepository;
import br.com.t3privacyguard.persistence.RemediationExecutionRepository;
import java.time.Instant;
import java.util.List;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IncidentRetentionService {
    private final IncidentRepository incidents;
    private final ActionProposalRepository actions;
    private final PolicyDecisionRepository decisions;
    private final RemediationExecutionRepository remediations;
    private final ExecutionTraceEventRepository traces;
    private final AuditEventRepository audits;
    private final IncidentRetentionProperties properties;

    public IncidentRetentionService(
        IncidentRepository incidents,
        ActionProposalRepository actions,
        PolicyDecisionRepository decisions,
        RemediationExecutionRepository remediations,
        ExecutionTraceEventRepository traces,
        AuditEventRepository audits,
        IncidentRetentionProperties properties
    ) {
        this.incidents = incidents;
        this.actions = actions;
        this.decisions = decisions;
        this.remediations = remediations;
        this.traces = traces;
        this.audits = audits;
        this.properties = properties;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void initializeRetention() {
        List<IncidentEntity> legacy = incidents.findByExpiresAtIsNull();
        for (IncidentEntity incident : legacy) {
            incident.assignExpiresAtIfMissing(incident.getCreatedAt().plus(properties.retention()));
        }
        if (!legacy.isEmpty()) incidents.saveAll(legacy);
        purgeExpiredAt(Instant.now());
    }

    @Scheduled(
        initialDelayString = "${privacy-guard.incident-retention.purge-initial-delay-ms:60000}",
        fixedDelayString = "${privacy-guard.incident-retention.purge-interval-ms:900000}"
    )
    @Transactional
    public void scheduledPurge() {
        purgeExpiredAt(Instant.now());
    }

    @Transactional
    public int purgeExpired() {
        return purgeExpiredAt(Instant.now());
    }

    private int purgeExpiredAt(Instant now) {
        List<IncidentEntity> expired = incidents.findByExpiresAtLessThanEqual(now);
        for (IncidentEntity incident : expired) purgeIncident(incident.getId());
        return expired.size();
    }

    private void purgeIncident(String incidentId) {
        List<String> actionIds = actions.findByIncidentIdOrderByCreatedAtAsc(incidentId).stream()
            .map(ActionProposalEntity::getId)
            .toList();
        traces.deleteAllByIncidentId(incidentId);
        if (!actionIds.isEmpty()) {
            remediations.deleteAllByActionProposalIdIn(actionIds);
            decisions.deleteAllByActionProposalIdIn(actionIds);
        }
        actions.deleteAllByIncidentId(incidentId);
        audits.deleteAllByIncidentId(incidentId);
        incidents.deleteById(incidentId);
    }
}
