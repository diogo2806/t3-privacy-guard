package br.com.t3privacyguard.persistence;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ExecutionTraceEventRepository extends JpaRepository<ExecutionTraceEventEntity, String> {
    List<ExecutionTraceEventEntity> findByIncidentIdAndActionIdOrderByCreatedAtAsc(String incidentId, String actionId);
}
