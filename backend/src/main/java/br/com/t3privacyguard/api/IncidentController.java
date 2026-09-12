package br.com.t3privacyguard.api;

import br.com.t3privacyguard.api.ApiModels.*;
import br.com.t3privacyguard.service.IncidentService;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/incidents")
public class IncidentController {
    private final IncidentService service;
    public IncidentController(IncidentService service) { this.service = service; }

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

    @PostMapping("/{incidentId}/actions/{actionId}/authorize-remediation")
    public RemediationAuthorizationResponse authorizeRemediation(@PathVariable String incidentId, @PathVariable String actionId) { return service.authorizeRemediation(incidentId, actionId); }

    @GetMapping("/{incidentId}/history")
    public List<AuditResponse> history(@PathVariable String incidentId) { return service.history(incidentId); }
}
