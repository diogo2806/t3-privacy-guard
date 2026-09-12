package br.com.t3privacyguard.api;

import br.com.t3privacyguard.api.ApiModels.ActionResponse;
import br.com.t3privacyguard.api.ApiModels.AuditResponse;
import br.com.t3privacyguard.api.ApiModels.CreateActionRequest;
import br.com.t3privacyguard.api.ApiModels.CreateIncidentRequest;
import br.com.t3privacyguard.api.ApiModels.DecisionResponse;
import br.com.t3privacyguard.api.ApiModels.ExecutionTraceResponse;
import br.com.t3privacyguard.api.ApiModels.IncidentResponse;
import br.com.t3privacyguard.api.ApiModels.RemediationAuthorizationResponse;
import br.com.t3privacyguard.api.ApiModels.RemediationExecutionResponse;
import br.com.t3privacyguard.service.IncidentService;
import br.com.t3privacyguard.service.RemediationQueryService;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/incidents")
public class IncidentController {
    private final IncidentService service;
    private final RemediationQueryService remediationQuery;

    public IncidentController(IncidentService service, RemediationQueryService remediationQuery) {
        this.service = service;
        this.remediationQuery = remediationQuery;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public IncidentResponse create(@Valid @RequestBody CreateIncidentRequest request) { return service.createIncident(request); }

    @GetMapping
    public List<IncidentResponse> list() { return service.listIncidents(); }

    @GetMapping("/{incidentId}")
    public IncidentResponse get(@PathVariable String incidentId) { return service.getIncident(incidentId); }

    @PostMapping("/{incidentId}/actions")
    @ResponseStatus(HttpStatus.CREATED)
    public ActionResponse addAction(@PathVariable String incidentId, @Valid @RequestBody CreateActionRequest request) { return service.addAction(incidentId, request); }

    @GetMapping("/{incidentId}/actions")
    public List<ActionResponse> actions(@PathVariable String incidentId) { return service.listActions(incidentId); }

    @PostMapping("/{incidentId}/actions/{actionId}/evaluate")
    public DecisionResponse evaluate(@PathVariable String incidentId, @PathVariable String actionId) { return service.evaluate(incidentId, actionId); }

    @GetMapping("/{incidentId}/actions/{actionId}/decision")
    public DecisionResponse decision(@PathVariable String incidentId, @PathVariable String actionId) { return service.getDecision(incidentId, actionId); }

    @PostMapping("/{incidentId}/actions/{actionId}/authorize-remediation")
    public RemediationAuthorizationResponse authorizeRemediation(@PathVariable String incidentId, @PathVariable String actionId) { return service.authorizeRemediation(incidentId, actionId); }

    @PostMapping("/{incidentId}/actions/{actionId}/execute-remediation")
    public RemediationExecutionResponse executeRemediation(@PathVariable String incidentId, @PathVariable String actionId) { return service.executeRemediation(incidentId, actionId); }

    @PostMapping("/{incidentId}/actions/{actionId}/verify-remediation")
    public RemediationExecutionResponse verifyRemediation(@PathVariable String incidentId, @PathVariable String actionId) { return service.verifyRemediation(incidentId, actionId); }

    @GetMapping("/{incidentId}/actions/{actionId}/remediation")
    public RemediationExecutionResponse remediation(@PathVariable String incidentId, @PathVariable String actionId) {
        return remediationQuery.get(incidentId, actionId);
    }

    @GetMapping("/{incidentId}/actions/{actionId}/trace")
    public List<ExecutionTraceResponse> executionTrace(@PathVariable String incidentId, @PathVariable String actionId) {
        return service.executionTrace(incidentId, actionId);
    }

    @GetMapping("/{incidentId}/history")
    public List<AuditResponse> history(@PathVariable String incidentId) { return service.history(incidentId); }
}
