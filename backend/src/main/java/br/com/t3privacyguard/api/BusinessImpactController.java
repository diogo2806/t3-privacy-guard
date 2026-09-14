package br.com.t3privacyguard.api;

import br.com.t3privacyguard.api.BusinessImpactModels.BusinessImpactResponse;
import br.com.t3privacyguard.service.BusinessImpactService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/business-impact")
public class BusinessImpactController {
    private final BusinessImpactService service;

    public BusinessImpactController(BusinessImpactService service) {
        this.service = service;
    }

    @GetMapping
    public BusinessImpactResponse impact(@RequestParam(defaultValue = "retained") String window) {
        return service.getImpact(window);
    }
}
