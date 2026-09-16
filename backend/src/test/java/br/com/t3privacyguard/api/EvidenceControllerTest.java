package br.com.t3privacyguard.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.service.EvidenceNotFoundException;
import br.com.t3privacyguard.service.EvidenceService;
import br.com.t3privacyguard.service.EvidenceService.EvidenceResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class EvidenceControllerTest {
    @Test
    void returnsNoContentWhenLiveEvidenceHasNotBeenGenerated() {
        EvidenceService service = mock(EvidenceService.class);
        when(service.latest()).thenThrow(new EvidenceNotFoundException("No live T3N evidence has been generated yet."));

        ResponseEntity<EvidenceResponse> response = new EvidenceController(service).latest();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(response.getBody()).isNull();
    }
}
