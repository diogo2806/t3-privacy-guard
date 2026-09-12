package br.com.t3privacyguard.persistence;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RemediationExecutionRepository extends JpaRepository<RemediationExecutionEntity,String>{
    Optional<RemediationExecutionEntity> findByActionProposalId(String actionProposalId);
}
