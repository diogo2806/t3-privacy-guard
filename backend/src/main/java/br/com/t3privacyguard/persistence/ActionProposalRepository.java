package br.com.t3privacyguard.persistence;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ActionProposalRepository extends JpaRepository<ActionProposalEntity, String> {
    Optional<ActionProposalEntity> findByRequestId(String requestId);
    List<ActionProposalEntity> findByIncidentIdOrderByCreatedAtAsc(String incidentId);
}
