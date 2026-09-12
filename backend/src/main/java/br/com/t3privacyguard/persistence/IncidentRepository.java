package br.com.t3privacyguard.persistence;

import org.springframework.data.jpa.repository.JpaRepository;

public interface IncidentRepository extends JpaRepository<IncidentEntity, String> {}
