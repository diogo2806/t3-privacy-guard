package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.api.ApiModels.IncidentIntakeRequest;
import br.com.t3privacyguard.api.ApiModels.IncidentResponse;
import br.com.t3privacyguard.audit.AuditIntegrityService;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.privacy.IncidentDataMinimizer;
import br.com.t3privacyguard.security.IncidentIntakePrincipal;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class IncidentIntakeCreationService {
    private static final String SOURCE_PREFIX = "Approved integration: ";

    private final IncidentService incidents;
    private final IncidentRepository incidentRepository;
    private final AuditIntegrityService auditIntegrity;
    private final IncidentDataMinimizer minimizer;

    public IncidentIntakeCreationService(
        IncidentService incidents,
        IncidentRepository incidentRepository,
        AuditIntegrityService auditIntegrity,
        IncidentDataMinimizer minimizer
    ) {
        this.incidents = incidents;
        this.incidentRepository = incidentRepository;
        this.auditIntegrity = auditIntegrity;
        this.minimizer = minimizer;
    }

    @Transactional
    public IncidentResponse create(IncidentIntakePrincipal principal, IncidentIntakeRequest request) {
        String source = SOURCE_PREFIX + principal.displayName();
        IncidentResponse created = incidents.createIncident(new CreateIncidentRequest(
            request.title(),
            request.severity(),
            request.summary(),
            source
        ));

        IncidentEntity entity = incidentRepository.findByIdForUpdate(created.id())
            .orElseThrow(() -> new IllegalStateException("Newly created incident could not be reloaded"));
        entity.assignExternalProvenance(principal.integrationId(), request.externalEventId().trim());
        incidentRepository.saveAndFlush(entity);
        auditIntegrity.append(
            created.id(),
            "EXTERNAL_INCIDENT_RECEIVED",
            minimizer.sanitizeAuditMessage("Incident received from approved integration " + principal.displayName())
        );
        return created;
    }
}
