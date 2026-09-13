package br.com.t3privacyguard.persistence;

import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ActionProposalRepository extends JpaRepository<ActionProposalEntity, String> {
    Optional<ActionProposalEntity> findByRequestId(String requestId);
    List<ActionProposalEntity> findByIncidentIdOrderByCreatedAtAsc(String incidentId);
    void deleteAllByIncidentId(String incidentId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select a from ActionProposalEntity a where a.id = :id")
    Optional<ActionProposalEntity> findByIdForExecutionClaim(@Param("id") String id);
}
