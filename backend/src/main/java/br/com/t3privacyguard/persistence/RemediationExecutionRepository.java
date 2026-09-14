package br.com.t3privacyguard.persistence;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RemediationExecutionRepository extends JpaRepository<RemediationExecutionEntity,String>{
    Optional<RemediationExecutionEntity> findByActionProposalId(String actionProposalId);
    List<RemediationExecutionEntity> findByLastAttemptAtBetweenOrderByLastAttemptAtAsc(Instant from, Instant to);
    void deleteAllByActionProposalIdIn(List<String> actionProposalIds);
}
