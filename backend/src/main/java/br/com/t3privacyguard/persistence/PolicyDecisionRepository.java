package br.com.t3privacyguard.persistence;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PolicyDecisionRepository extends JpaRepository<PolicyDecisionEntity, String> {
    Optional<PolicyDecisionEntity> findByActionProposalId(String actionProposalId);
    void deleteAllByActionProposalIdIn(List<String> actionProposalIds);
}
