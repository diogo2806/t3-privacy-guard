package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.ApiModels.ExecutionTraceResponse;
import br.com.t3privacyguard.observability.TraceContext;
import br.com.t3privacyguard.persistence.ActionProposalEntity;
import br.com.t3privacyguard.persistence.ExecutionTraceEventEntity;
import br.com.t3privacyguard.persistence.ExecutionTraceEventRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ExecutionTraceService {
    private final ExecutionTraceEventRepository traces;

    public ExecutionTraceService(ExecutionTraceEventRepository traces) {
        this.traces = traces;
    }

    @Transactional
    public void record(ActionProposalEntity action, String stage, String state, String reasonCode, Long durationMs) {
        save(action, stage, state, reasonCode, durationMs);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordFailure(ActionProposalEntity action, String stage, String state, String reasonCode, Long durationMs) {
        save(action, stage, state, reasonCode, durationMs);
    }

    @Transactional(readOnly = true)
    public List<ExecutionTraceResponse> timeline(String incidentId, String actionId) {
        return traces.findByIncidentIdAndActionIdOrderByCreatedAtAsc(incidentId, actionId).stream()
            .map(event -> new ExecutionTraceResponse(
                event.getId(),
                event.getIncidentId(),
                event.getActionId(),
                event.getTraceId(),
                event.getRequestId(),
                event.getStage(),
                event.getState(),
                event.getReasonCode(),
                event.getDurationMs(),
                event.getCreatedAt()
            ))
            .toList();
    }

    private void save(ActionProposalEntity action, String stage, String state, String reasonCode, Long durationMs) {
        traces.save(new ExecutionTraceEventEntity(
            UUID.randomUUID().toString(),
            action.getIncidentId(),
            action.getId(),
            safe(action.getRequestId(), 128),
            safe(TraceContext.currentOrGenerate(), 64),
            safe(stage, 64),
            safe(state, 32),
            blankToNull(safe(reasonCode, 80)),
            durationMs == null ? null : Math.max(0L, durationMs),
            Instant.now()
        ));
    }

    private static String safe(String value, int max) {
        String normalized = value == null ? "" : value.replaceAll("[^A-Za-z0-9._:-]", "_");
        return normalized.substring(0, Math.min(normalized.length(), max));
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }
}
