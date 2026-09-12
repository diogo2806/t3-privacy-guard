package br.com.t3privacyguard.api;

import br.com.t3privacyguard.api.ApiModels.AgentAnalysisResponse;
import br.com.t3privacyguard.api.ApiModels.AnalyzeAgentRequest;
import br.com.t3privacyguard.service.AgentAnalysisService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/agent")
public class AgentController {
    private final AgentAnalysisService service;

    public AgentController(AgentAnalysisService service) {
        this.service = service;
    }

    @PostMapping("/analyze")
    public ResponseEntity<AgentAnalysisResponse> analyze(@Valid @RequestBody AnalyzeAgentRequest request) {
        return ResponseEntity.ok(service.analyze(request.prompt()));
    }
}
