package br.com.t3privacyguard.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditChainHeadRepository extends JpaRepository<AuditChainHeadEntity, String> {}
