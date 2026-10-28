package br.com.t3privacyguard.api;

import br.com.t3privacyguard.integration.PolicyAdministrationException;
import br.com.t3privacyguard.integration.PolicyAdministrationException.Kind;
import br.com.t3privacyguard.integration.RuntimePolicyAdminClient;
import br.com.t3privacyguard.integration.RuntimePolicyAdminClient.PolicyChange;
import br.com.t3privacyguard.integration.RuntimePolicyAdminClient.PolicyHistoryEntry;
import br.com.t3privacyguard.integration.RuntimePolicyAdminClient.PolicyValidation;
import br.com.t3privacyguard.integration.RuntimePolicyAdminClient.PolicyVersion;
import br.com.t3privacyguard.integration.RuntimePolicyAdminClient.PolicyView;
import br.com.t3privacyguard.security.HumanSeparationOfDutiesService;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Policy editor API. Reads are open to POLICY_ADMIN and AUDITOR, changes to POLICY_ADMIN (see SecurityConfig).
 * guard-runtime validates and versions every document; the authenticated principal is recorded as the requester.
 */
@RestController
@RequestMapping("/api/policy")
public class PolicyController {
    private static final int MAX_HISTORY_LIMIT = 200;

    private final RuntimePolicyAdminClient policies;

    public PolicyController(RuntimePolicyAdminClient policies) {
        this.policies = policies;
    }

    @GetMapping
    public PolicyView current() {
        return policies.current();
    }

    @GetMapping("/history")
    public List<PolicyHistoryEntry> history(@RequestParam(defaultValue = "50") int limit) {
        return policies.history(Math.max(1, Math.min(limit, MAX_HISTORY_LIMIT)));
    }

    @GetMapping("/versions/{version}")
    public PolicyVersion version(@PathVariable String version) {
        return policies.version(version);
    }

    @PostMapping("/validate")
    public PolicyValidation validate(@Valid @RequestBody PolicyDocumentRequest request) {
        return policies.validate(requireObject(request.document()));
    }

    @PostMapping("/publish")
    public PolicyChange publish(@Valid @RequestBody PolicyPublishRequest request, Authentication authentication) {
        return policies.publish(requireObject(request.document()), request.expectedCurrentHash(),
            HumanSeparationOfDutiesService.requireAuthenticatedPrincipal(authentication));
    }

    @PostMapping("/rollback")
    public PolicyChange rollback(@Valid @RequestBody PolicyRollbackRequest request, Authentication authentication) {
        return policies.rollback(request.version().trim(), request.expectedCurrentHash(),
            HumanSeparationOfDutiesService.requireAuthenticatedPrincipal(authentication));
    }

    private static JsonNode requireObject(JsonNode document) {
        if (document == null || !document.isObject()) {
            throw new PolicyAdministrationException(Kind.INVALID, "INVALID_INPUT", "The policy document must be a JSON object.");
        }
        return document;
    }

    public record PolicyDocumentRequest(@NotNull JsonNode document) {}

    public record PolicyPublishRequest(@NotNull JsonNode document, String expectedCurrentHash) {}

    public record PolicyRollbackRequest(@NotBlank String version, String expectedCurrentHash) {}
}
