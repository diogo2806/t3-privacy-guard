package br.com.t3privacyguard.persistence;

import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditChainHeadRepository extends JpaRepository<AuditChainHeadEntity, String> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select head from AuditChainHeadEntity head where head.incidentId = :incidentId")
    Optional<AuditChainHeadEntity> findForUpdate(@Param("incidentId") String incidentId);
}
