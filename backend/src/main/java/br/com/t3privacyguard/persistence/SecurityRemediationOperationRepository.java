package br.com.t3privacyguard.persistence;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityRemediationOperationRepository extends JpaRepository<SecurityRemediationOperationEntity, String> {
    Optional<SecurityRemediationOperationEntity> findByRequestId(String requestId);
}
