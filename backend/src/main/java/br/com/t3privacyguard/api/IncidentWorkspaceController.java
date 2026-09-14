package br.com.t3privacyguard.api;

import br.com.t3privacyguard.api.IncidentWorkspaceModels.IncidentWorkspaceResponse;
import br.com.t3privacyguard.service.IncidentWorkspaceService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/incident-workspace")
public class IncidentWorkspaceController {
    private final IncidentWorkspaceService service;

    public IncidentWorkspaceController(IncidentWorkspaceService service) {
        this.service = service;
    }

    @GetMapping
    public IncidentWorkspaceResponse workspace() {
        return service.getWorkspace();
    }
}
