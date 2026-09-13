package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.ApiModels.AgentAnalysisResponse;
import br.com.t3privacyguard.api.ApiModels.CreateActionRequest;
import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.domain.Severity;
import br.com.t3privacyguard.integration.GatewayAgentClient;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class AgentAnalysisService {
    private final GatewayAgentClient agentGateway;
    private final IncidentService incidents;

    public AgentAnalysisService(GatewayAgentClient agentGateway, IncidentService incidents) {
        this.agentGateway = agentGateway;
        this.incidents = incidents;
    }

    public AgentAnalysisResponse analyze(String prompt) {
        String normalized = prompt == null ? "" : prompt.trim();
        if (normalized.isBlank() || normalized.length() > 4000) {
            throw new IllegalArgumentException("Prompt must contain between 1 and 4000 characters");
        }

        var generated = agentGateway.propose(normalized);
        var proposal = generated.proposal();
        List<String> fields = proposal.fields() == null ? List.of() : proposal.fields();
        List<String> privateRefs = proposal.privateRefs() == null ? List.of() : proposal.privateRefs();

        var incident = incidents.createIncident(new CreateIncidentRequest(
            "AI agent action proposal",
            Severity.CRITICAL,
            "An untrusted prompt was interpreted by the configured AI agent. The incident keeps a minimized operational description for a bounded retention period; resolved private profile values remain outside the model and application layers.",
            "AI agent " + generated.provider()
        ));
        var action = incidents.addAction(incident.id(), new CreateActionRequest(
            "ai-" + UUID.randomUUID(),
            proposal.action(),
            proposal.resource(),
            proposal.purpose(),
            proposal.host(),
            fields,
            privateRefs
        ));
        var decision = incidents.evaluate(incident.id(), action.id());
        var refreshedAction = incidents.listActions(incident.id()).stream()
            .filter(item -> item.id().equals(action.id()))
            .findFirst()
            .orElse(action);
        return new AgentAnalysisResponse(generated.provider(), generated.model(), incident, refreshedAction, decision);
    }
}
