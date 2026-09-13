package br.com.t3privacyguard.persistence;

import jakarta.persistence.LockModeType;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IncidentRepository extends JpaRepository<IncidentEntity, String> {
    List<IncidentEntity> findByExpiresAtIsNull();
    List<IncidentEntity> findByExpiresAtLessThanEqual(Instant now);
    List<IncidentEntity> findByExpiresAtAfterOrderByCreatedAtDesc(Instant now);
    Optional<IncidentEntity> findByIdAndExpiresAtAfter(String id, Instant now);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select incident from IncidentEntity incident where incident.id = :incidentId")
    Optional<IncidentEntity> findForAuditUpdate(@Param("incidentId") String incidentId);
}
