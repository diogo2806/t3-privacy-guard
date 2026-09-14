package br.com.t3privacyguard.api;

import br.com.t3privacyguard.api.ApiModels.IncidentIntakeRequest;
import br.com.t3privacyguard.api.ApiModels.IncidentIntakeResponse;
import br.com.t3privacyguard.security.IncidentIntakePrincipal;
import br.com.t3privacyguard.service.IncidentIntakeService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/integrations/incidents")
public class IncidentIntakeController {
    private final IncidentIntakeService intake;

    public IncidentIntakeController(IncidentIntakeService intake) {
        this.intake = intake;
    }

    @PostMapping
    public ResponseEntity<IncidentIntakeResponse> receive(
        @AuthenticationPrincipal IncidentIntakePrincipal principal,
        @Valid @RequestBody IncidentIntakeRequest request
    ) {
        if (principal == null) throw new IllegalStateException("Authenticated integration principal is required");
        IncidentIntakeResponse response = intake.receive(principal, request);
        return ResponseEntity.status(response.replayed() ? HttpStatus.OK : HttpStatus.CREATED).body(response);
    }
}
