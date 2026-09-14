package br.com.t3privacyguard.security;

import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.service.IncidentNotFoundException;
import br.com.t3privacyguard.service.PolicyDeniedException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class HumanSeparationOfDutiesService {
    private final ActionProposalRepository actions;
    private final boolean enterpriseSodEnabled;

    public HumanSeparationOfDutiesService(
        ActionProposalRepository actions,
        @Value("${privacy-guard.iam.enterprise-sod-enabled:false}") boolean enterpriseSodEnabled
    ) {
        this.actions = actions;
        this.enterpriseSodEnabled = enterpriseSodEnabled;
    }

    @Transactional(readOnly = true)
    public String requireExecutorPrincipal(String actionId, Authentication authentication) {
        String principal = requireAuthenticatedPrincipal(authentication);
        ActionProposalEntity action = actions.findById(actionId)
            .orElseThrow(() -> new IncidentNotFoundException("Action proposal not found"));
        if (enterpriseSodEnabled && principal.equals(action.getRemediationAuthorizedBy())) {
            throw new PolicyDeniedException("Separation of duties requires a different principal to execute or verify a remediation than the principal who authorized it");
        }
        return principal;
    }

    public boolean enterpriseSodEnabled() {
        return enterpriseSodEnabled;
    }

    public static String requireAuthenticatedPrincipal(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated() || authentication instanceof AnonymousAuthenticationToken) {
            throw new PolicyDeniedException("Authenticated human principal is required");
        }
        try {
            return ActionProposalEntity.canonicalizeAuthenticatedPrincipal(authentication.getName());
        } catch (IllegalArgumentException exception) {
            throw new PolicyDeniedException("Authenticated human principal is required");
        }
    }
}
