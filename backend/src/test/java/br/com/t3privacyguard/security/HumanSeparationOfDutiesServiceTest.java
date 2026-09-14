package br.com.t3privacyguard.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ActionProposalRepository;
import br.com.t3privacyguard.service.IncidentNotFoundException;
import br.com.t3privacyguard.service.PolicyDeniedException;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

class HumanSeparationOfDutiesServiceTest {
    private static final String INCIDENT_ID = "incident-1";
    private static final String ACTION_ID = "action-1";

    @Test
    void enterpriseModeBlocksExecutorWhenSamePrincipalAuthorizedRemediation() {
        ActionProposalRepository actions = mock(ActionProposalRepository.class);
        when(actions.findById(ACTION_ID)).thenReturn(Optional.of(authorizedAction("approver-01")));
        HumanSeparationOfDutiesService service = new HumanSeparationOfDutiesService(actions, true);

        var authentication = authenticated("approver-01");

        assertThatThrownBy(() -> service.requireExecutorPrincipal(INCIDENT_ID, ACTION_ID, authentication))
            .isInstanceOf(PolicyDeniedException.class)
            .hasMessageContaining("different principal");
    }

    @Test
    void enterpriseModeAllowsDifferentExecutorPrincipal() {
        ActionProposalRepository actions = mock(ActionProposalRepository.class);
        when(actions.findById(ACTION_ID)).thenReturn(Optional.of(authorizedAction("approver-01")));
        HumanSeparationOfDutiesService service = new HumanSeparationOfDutiesService(actions, true);

        String principal = service.requireExecutorPrincipal(INCIDENT_ID, ACTION_ID, authenticated("executor-01"));

        assertThat(principal).isEqualTo("executor-01");
    }

    @Test
    void localDemoModeKeepsSingleConfiguredPrincipalCompatible() {
        ActionProposalRepository actions = mock(ActionProposalRepository.class);
        when(actions.findById(ACTION_ID)).thenReturn(Optional.of(authorizedAction("test-operator")));
        HumanSeparationOfDutiesService service = new HumanSeparationOfDutiesService(actions, false);

        String principal = service.requireExecutorPrincipal(INCIDENT_ID, ACTION_ID, authenticated("test-operator"));

        assertThat(principal).isEqualTo("test-operator");
    }

    @Test
    void mismatchedIncidentIsRejectedBeforePrincipalComparison() {
        ActionProposalRepository actions = mock(ActionProposalRepository.class);
        when(actions.findById(ACTION_ID)).thenReturn(Optional.of(authorizedAction("approver-01")));
        HumanSeparationOfDutiesService service = new HumanSeparationOfDutiesService(actions, true);

        assertThatThrownBy(() -> service.requireExecutorPrincipal("other-incident", ACTION_ID, authenticated("executor-01")))
            .isInstanceOf(IncidentNotFoundException.class)
            .hasMessageContaining("not found for incident");
    }

    private static UsernamePasswordAuthenticationToken authenticated(String principal) {
        return new UsernamePasswordAuthenticationToken(
            principal,
            "n/a",
            AuthorityUtils.createAuthorityList("ROLE_EXECUTOR")
        );
    }

    private static ActionProposalEntity authorizedAction(String principal) {
        ActionProposalEntity action = new ActionProposalEntity(
            ACTION_ID,
            INCIDENT_ID,
            "request-1",
            "revoke-credential",
            "credential:synthetic",
            "incident-remediation",
            "security.example",
            "[\"incident_id\",\"credential_id\",\"reason\"]",
            "{\"incident_id\":\"incident-1\",\"credential_id\":\"cred-1\",\"reason\":\"test\"}",
            "[]",
            Instant.parse("2026-09-14T12:00:00Z")
        );
        action.markEvaluated();
        action.authorizeRemediation(principal, Instant.parse("2026-09-14T12:01:00Z"));
        return action;
    }
}
