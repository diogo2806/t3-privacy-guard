package br.com.t3privacyguard.service;

import br.com.t3privacyguard.api.ApiModels.AuditEvidenceResponse;
import br.com.t3privacyguard.api.ApiModels.AuditIntegrityResponse;
import br.com.t3privacyguard.api.ApiModels.AuditProvenance;
import br.com.t3privacyguard.api.ApiModels.LocalAuditEvidence;
import br.com.t3privacyguard.api.ApiModels.T3nActivityEvidence;
import br.com.t3privacyguard.audit.AuditIntegrityService;
import br.com.t3privacyguard.domain.AuditReconciliationStatus;
import br.com.t3privacyguard.integration.GatewaySystemClient;
import br.com.t3privacyguard.integration.GatewaySystemClient.ActivityEvent;
import br.com.t3privacyguard.integration.GatewaySystemClient.ActivityPage;
import br.com.t3privacyguard.persistence.AuditEventEntity;
import br.com.t3privacyguard.persistence.IncidentEntity;
import br.com.t3privacyguard.persistence.IncidentRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditEvidenceService {
    private static final int MAX_LIMIT = 200;
    private static final long CLOCK_SKEW_MARGIN_SECONDS = 300;
    private static final String EVALUATE_ACTION = "evaluate-action";
    private static final String EXECUTE_REMEDIATION = "execute-remediation";
    private static final String VERIFY_REMEDIATION = "verify-remediation";
    private static final Set<String> PRIVACY_GUARD_FUNCTIONS = Set.of(
        EVALUATE_ACTION,
        EXECUTE_REMEDIATION,
        VERIFY_REMEDIATION
    );

    private final IncidentRepository incidents;
    private final AuditIntegrityService auditIntegrity;
    private final GatewaySystemClient gateway;

    public AuditEvidenceService(IncidentRepository incidents, AuditIntegrityService auditIntegrity, GatewaySystemClient gateway) {
        this.incidents = incidents;
        this.auditIntegrity = auditIntegrity;
        this.gateway = gateway;
    }

    @Transactional(readOnly = true)
    public AuditEvidenceResponse read(String incidentId, int requestedLimit) {
        if (requestedLimit < 1 || requestedLimit > MAX_LIMIT) throw new IllegalArgumentException("Activity limit must be between 1 and 200");
        IncidentEntity incident = incidents.findByIdAndExpiresAtAfter(incidentId, Instant.now())
            .orElseThrow(() -> new IncidentNotFoundException("Incident not found"));
        AuditIntegrityService.Verification integrity = auditIntegrity.verify(incidentId);
        List<AuditEventEntity> local = integrity.events();
        AuditIntegrityResponse integrityResponse = integrityResponse(integrity);

        Optional<GatewaySystemClient.TenantStatus> tenant = gateway.tenantStatus();
        Optional<GatewaySystemClient.AgentStatus> agent = gateway.agentStatus();
        Optional<GatewaySystemClient.ExecutorStatus> executor = gateway.executorStatus();
        Optional<GatewaySystemClient.ContractIdentity> contract = gateway.contractIdentity();
        long fromMs = incident.getCreatedAt().minusSeconds(CLOCK_SKEW_MARGIN_SECONDS).toEpochMilli();
        long toMs = Instant.now().plusSeconds(CLOCK_SKEW_MARGIN_SECONDS).toEpochMilli();
        Optional<ActivityPage> activity = tenant.filter(GatewaySystemClient.TenantStatus::ready)
            .flatMap(ignored -> contract)
            .flatMap(ignored -> gateway.activity(fromMs, toMs, requestedLimit));

        if (activity.isEmpty() || tenant.isEmpty() || contract.isEmpty()) {
            return degraded(local, integrityResponse, requestedLimit);
        }

        String tenantDid = tenant.get().tenantDid();
        String contractId = contract.get().contractId();
        if (blank(tenantDid) || blank(contractId)) return degraded(local, integrityResponse, requestedLimit);

        Optional<String> proposalAgentDid = agent
            .filter(GatewaySystemClient.AgentStatus::ready)
            .map(GatewaySystemClient.AgentStatus::agentDid)
            .filter(did -> !blank(did));
        Optional<String> protectedExecutorDid = executor
            .filter(GatewaySystemClient.ExecutorStatus::ready)
            .map(GatewaySystemClient.ExecutorStatus::executorDid)
            .filter(did -> !blank(did));

        ActivityPage page = activity.get();
        List<ActivityEvent> relevant = page.events().stream()
            .filter(event -> "agent".equals(event.callerType()))
            .filter(event -> tenantDid.equals(event.onBehalfOfDid()))
            .filter(event -> contractId.equals(event.contractId()))
            .filter(event -> PRIVACY_GUARD_FUNCTIONS.contains(event.function()))
            .sorted(Comparator.comparingLong(ActivityEvent::sequence).reversed())
            .toList();

        Map<Long, ActivityEvent> bySequence = new HashMap<>();
        relevant.forEach(event -> bySequence.putIfAbsent(event.sequence(), event));
        Set<Long> matchedSequences = new HashSet<>();
        List<LocalAuditEvidence> localEvidence = new ArrayList<>(local.size());

        int matched = 0;
        int unmatched = 0;
        int localOnly = 0;
        for (AuditEventEntity event : local) {
            AuditReconciliationStatus status;
            Long matchedSequence = null;
            if (event.getT3nFunction() == null) {
                status = AuditReconciliationStatus.LOCAL_ONLY;
                localOnly += 1;
            } else {
                ActivityEvent candidate = event.getT3nSequence() == null ? null : bySequence.get(event.getT3nSequence());
                boolean exact = candidate != null
                    && event.getT3nFunction().equals(candidate.function())
                    && event.getT3nHash() != null
                    && event.getT3nHash().equals(candidate.hash())
                    && expectedActorDid(event.getT3nFunction(), proposalAgentDid, protectedExecutorDid)
                        .map(expectedDid -> expectedDid.equals(candidate.actorDid()))
                        .orElse(false);
                if (exact) {
                    status = AuditReconciliationStatus.MATCHED;
                    matched += 1;
                    matchedSequence = candidate.sequence();
                    matchedSequences.add(candidate.sequence());
                } else {
                    status = AuditReconciliationStatus.UNMATCHED;
                    unmatched += 1;
                }
            }
            localEvidence.add(localEvidence(event, status, matchedSequence));
        }

        List<T3nActivityEvidence> t3nEvidence = relevant.stream()
            .map(event -> t3nEvidence(event, matchedSequences.contains(event.sequence())
                ? AuditReconciliationStatus.MATCHED
                : AuditReconciliationStatus.T3N_ONLY))
            .toList();
        int t3nOnly = (int) t3nEvidence.stream().filter(event -> event.status() == AuditReconciliationStatus.T3N_ONLY).count();

        String message = provenanceMessage(page.complete(), proposalAgentDid.isPresent(), protectedExecutorDid.isPresent());
        AuditProvenance provenance = new AuditProvenance(true, true, page.complete(), matched, unmatched, localOnly, t3nOnly, message);
        return new AuditEvidenceResponse(localEvidence, t3nEvidence, provenance, integrityResponse, page.nextSequence(), requestedLimit);
    }

    private static Optional<String> expectedActorDid(
        String function,
        Optional<String> proposalAgentDid,
        Optional<String> protectedExecutorDid
    ) {
        return switch (function) {
            case EVALUATE_ACTION -> proposalAgentDid;
            case EXECUTE_REMEDIATION, VERIFY_REMEDIATION -> protectedExecutorDid;
            default -> Optional.empty();
        };
    }

    private static String provenanceMessage(boolean complete, boolean proposalAgentAvailable, boolean protectedExecutorAvailable) {
        boolean principalsAvailable = proposalAgentAvailable && protectedExecutorAvailable;
        if (!complete && !principalsAvailable) {
            return "T3N activity is available, but the bounded activity window was truncated and one or more canonical principal identities are unavailable. Affected operations cannot be matched, and unmatched evidence is not proof that no network event exists.";
        }
        if (!complete) {
            return "T3N activity is available, but the bounded activity window was truncated. Unmatched evidence is not proof that no network event exists.";
        }
        if (!principalsAvailable) {
            return "T3N activity is available, but one or more canonical principal identities are unavailable. Events remain visible, but affected operations cannot be matched.";
        }
        return "T3N activity is available. Reconciliation requires exact sequence, hash, contract, function and the canonical actor for that function.";
    }

    private AuditEvidenceResponse degraded(List<AuditEventEntity> local, AuditIntegrityResponse integrity, int limit) {
        List<LocalAuditEvidence> localEvidence = local.stream().map(event -> {
            AuditReconciliationStatus status = event.getT3nFunction() == null
                ? AuditReconciliationStatus.LOCAL_ONLY
                : AuditReconciliationStatus.UNMATCHED;
            return localEvidence(event, status, null);
        }).toList();
        int unmatched = (int) localEvidence.stream().filter(event -> event.status() == AuditReconciliationStatus.UNMATCHED).count();
        int localOnly = localEvidence.size() - unmatched;
        AuditProvenance provenance = new AuditProvenance(
            true,
            false,
            false,
            0,
            unmatched,
            localOnly,
            0,
            "T3N activity temporarily unavailable. Local business audit remains available; network provenance was not verified."
        );
        return new AuditEvidenceResponse(localEvidence, List.of(), provenance, integrity, null, limit);
    }

    private static AuditIntegrityResponse integrityResponse(AuditIntegrityService.Verification verification) {
        return new AuditIntegrityResponse(
            verification.state(),
            verification.eventsChecked(),
            verification.head(),
            verification.version(),
            verification.detail()
        );
    }

    private static LocalAuditEvidence localEvidence(AuditEventEntity event, AuditReconciliationStatus status, Long matchedSequence) {
        return new LocalAuditEvidence(
            event.getId(),
            event.getIncidentId(),
            event.getType(),
            event.getMessage(),
            event.getCreatedAt(),
            status,
            event.getT3nSequence(),
            event.getT3nFunction(),
            matchedSequence
        );
    }

    private static T3nActivityEvidence t3nEvidence(ActivityEvent event, AuditReconciliationStatus status) {
        return new T3nActivityEvidence(
            event.sequence(),
            event.hash(),
            Instant.ofEpochMilli(event.timestampMs()),
            event.callerType(),
            event.actorDid(),
            event.onBehalfOfDid(),
            event.contractId(),
            event.function(),
            event.outcome(),
            status
        );
    }

    private static boolean blank(String value) { return value == null || value.isBlank(); }
}
