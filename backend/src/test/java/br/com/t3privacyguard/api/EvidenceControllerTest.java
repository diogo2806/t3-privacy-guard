package br.com.t3privacyguard.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import br.com.t3privacyguard.service.EvidenceService;
import br.com.t3privacyguard.service.EvidenceService.EvidenceAvailability;
import br.com.t3privacyguard.service.EvidenceService.EvidenceResponse;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

class EvidenceControllerTest {
    @Test
    void returnsNoContentWhenLiveEvidenceHasNotBeenGenerated() {
        EvidenceService service = mock(EvidenceService.class);
        when(service.latestState()).thenReturn(new EvidenceAvailability(false, null));

        ResponseEntity<EvidenceResponse> response = new EvidenceController(service).latest();

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(response.getBody()).isNull();
    }
}
