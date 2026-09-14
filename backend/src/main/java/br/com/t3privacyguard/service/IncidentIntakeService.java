package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.ApiModels.IncidentIntakeRequest;
import br.com.t3privacyguard.api.ApiModels.IncidentIntakeResponse;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import br.com.t3privacyguard.security.IncidentIntakePrincipal;
import java.time.Instant;
import java.util.Optional;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

@Service
public class IncidentIntakeService {
    private final IncidentRepository incidentRepository;
    private final IncidentService incidents;
    private final IncidentIntakeCreationService creation;

    public IncidentIntakeService(
        IncidentRepository incidentRepository,
        IncidentService incidents,
        IncidentIntakeCreationService creation
    ) {
        this.incidentRepository = incidentRepository;
        this.incidents = incidents;
        this.creation = creation;
    }

    public IncidentIntakeResponse receive(IncidentIntakePrincipal principal, IncidentIntakeRequest request) {
        String externalEventId = request.externalEventId().trim();
        Optional<IncidentEntity> existing = incidentRepository.findByIntegrationIdAndExternalEventId(
            principal.integrationId(), externalEventId
        );
        if (existing.isPresent()) return replay(existing.get());

        try {
            return new IncidentIntakeResponse(creation.create(principal, request), false);
        } catch (DataIntegrityViolationException concurrentReplay) {
            IncidentEntity winner = incidentRepository.findByIntegrationIdAndExternalEventId(principal.integrationId(), externalEventId)
                .orElseThrow(() -> new ConflictException("External event could not be accepted idempotently; retry with the same externalEventId"));
            return replay(winner);
        }
    }

    private IncidentIntakeResponse replay(IncidentEntity entity) {
        if (entity.getExpiresAt() == null || !entity.getExpiresAt().isAfter(Instant.now())) {
            throw new ExternalIncidentExpiredException();
        }
        return new IncidentIntakeResponse(incidents.getIncident(entity.getId()), true);
    }
}
