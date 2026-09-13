package br.com.t3privacyguard.persistence;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface IncidentRepository extends JpaRepository<IncidentEntity, String> {
    List<IncidentEntity> findByExpiresAtIsNull();
    List<IncidentEntity> findByExpiresAtLessThanEqual(Instant now);
    List<IncidentEntity> findByExpiresAtAfterOrderByCreatedAtDesc(Instant now);
    Optional<IncidentEntity> findByIdAndExpiresAtAfter(String id, Instant now);
}
