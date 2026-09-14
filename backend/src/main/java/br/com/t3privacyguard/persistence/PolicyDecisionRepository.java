package br.com.t3privacyguard.persistence;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PolicyDecisionRepository extends JpaRepository<PolicyDecisionEntity, String> {
    Optional<PolicyDecisionEntity> findByActionProposalId(String actionProposalId);
    List<PolicyDecisionEntity> findByEvaluatedAtBetweenOrderByEvaluatedAtAsc(Instant from, Instant to);
    void deleteAllByActionProposalIdIn(List<String> actionProposalIds);
}
