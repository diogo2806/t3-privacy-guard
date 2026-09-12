package br.com.t3privacyguard.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEventEntity, String> {
    List<AuditEventEntity> findByIncidentIdOrderByCreatedAtAsc(String incidentId);
}
