package br.com.t3privacyguard.api;

import br.com.t3privacyguard.service.EvidenceNotFoundException;
import br.com.t3privacyguard.service.EvidenceService;
import br.com.t3privacyguard.service.EvidenceService.EvidenceResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/evidence")
public class EvidenceController {
    private final EvidenceService service;

    public EvidenceController(EvidenceService service) {
        this.service = service;
    }

    @GetMapping("/latest")
    public ResponseEntity<EvidenceResponse> latest() {
        try {
            return ResponseEntity.ok(service.latest());
        } catch (EvidenceNotFoundException ex) {
            return ResponseEntity.noContent().build();
        }
    }
}
