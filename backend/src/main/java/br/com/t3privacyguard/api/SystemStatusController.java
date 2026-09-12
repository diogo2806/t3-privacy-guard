package br.com.t3privacyguard.api;

import br.com.t3privacyguard.service.SystemStatusService;
import br.com.t3privacyguard.service.SystemStatusService.SystemStatusResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/system")
public class SystemStatusController {
    private final SystemStatusService service;

    public SystemStatusController(SystemStatusService service) {
        this.service = service;
    }

    @GetMapping("/status")
    public SystemStatusResponse status() {
        return service.status();
    }
}
