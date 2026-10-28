package br.com.t3privacyguard.integration;

import br.com.t3privacyguard.integration.RuntimeStatusClient.DelegationStatus;
import br.com.t3privacyguard.integration.RuntimeStatusClient.EnterpriseIntegrationReadiness;
import br.com.t3privacyguard.integration.RuntimeStatusClient.EnterpriseVerificationContract;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Whether the external execution integration is ready: both endpoints configured, credentials present, and every
 * executable action's policy and the executor's grant allowing those hosts. Demo hosts never count as ready.
 */
final class EnterpriseIntegrationRules {
    static final List<EnterpriseVerificationContract> VERIFICATION_CONTRACTS = List.of(
        new EnterpriseVerificationContract("revoke-credential", "REVOKED"),
        new EnterpriseVerificationContract("notify-security", "DELIVERED")
    );
    private static final Set<String> DEMO_HOSTS = Set.of("postman-echo.com");

    private EnterpriseIntegrationRules() {}

    static List<String> executableActions() {
        return VERIFICATION_CONTRACTS.stream().map(EnterpriseVerificationContract::action).toList();
    }

    static EnterpriseIntegrationReadiness unknown(String checkedAt, String diagnosticCode) {
        return new EnterpriseIntegrationReadiness(
            "UNKNOWN", diagnosticCode, null, null, null, null, null, null, null, null, null,
            executableActions(), executableActions(), VERIFICATION_CONTRACTS, List.of(), checkedAt
        );
    }

    /** policyActions is the canonical policy's "actions" object as guard-runtime reports it. */
    static EnterpriseIntegrationReadiness evaluate(
        String executionHost,
        String verificationHost,
        boolean credentialConfigured,
        JsonNode policyActions,
        DelegationStatus executorDelegation,
        String checkedAt
    ) {
        List<String> executable = executableActions();
        List<String> evaluationOnly = new ArrayList<>();
        Iterator<String> names = policyActions.fieldNames();
        while (names.hasNext()) {
            String name = names.next();
            if (!executable.contains(name)) evaluationOnly.add(name);
        }
        evaluationOnly.sort(String::compareTo);
        List<JsonNode> rules = executable.stream().map(policyActions::get).filter(rule -> rule != null && rule.isObject()).toList();

        boolean executionConfigured = executionHost != null;
        boolean verificationConfigured = verificationHost != null;
        boolean policyAllowsExecutionHost = allRulesAllow(rules, executionHost);
        boolean policyAllowsVerificationHost = allRulesAllow(rules, verificationHost);
        boolean delegationUnknown = "UNKNOWN".equals(executorDelegation.memberState()) || "UNKNOWN".equals(executorDelegation.effectiveState());
        boolean delegationActive = "ACTIVE".equals(executorDelegation.memberState()) && "ACTIVE".equals(executorDelegation.effectiveState());
        Set<String> executorHosts = normalized(executorDelegation.allowedHosts());
        Boolean executorAllowsExecutionHost = delegationUnknown ? null : executionHost != null && delegationActive && executorHosts.contains(executionHost);
        Boolean executorAllowsVerificationHost = delegationUnknown ? null : verificationHost != null && delegationActive && executorHosts.contains(verificationHost);

        String state;
        String diagnosticCode = "NONE";
        if (!executionConfigured || !verificationConfigured || !credentialConfigured || isDemoHost(executionHost) || isDemoHost(verificationHost)) {
            state = "INCOMPLETE";
        } else if (delegationUnknown) {
            state = "UNKNOWN";
            diagnosticCode = "DELEGATION_UNAVAILABLE";
        } else if (rules.size() != executable.size() || !policyAllowsExecutionHost || !policyAllowsVerificationHost
            || !Boolean.TRUE.equals(executorAllowsExecutionHost) || !Boolean.TRUE.equals(executorAllowsVerificationHost)) {
            state = "MISMATCH";
        } else {
            state = "READY";
        }
        return new EnterpriseIntegrationReadiness(
            state, diagnosticCode, executionConfigured, verificationConfigured, credentialConfigured, executionHost, verificationHost,
            policyAllowsExecutionHost, policyAllowsVerificationHost, executorAllowsExecutionHost, executorAllowsVerificationHost,
            executable, executable, VERIFICATION_CONTRACTS, evaluationOnly, checkedAt
        );
    }

    /** The hosts every executable action's policy allows: the only destinations guard-runtime will call. */
    static List<String> remediationHosts(JsonNode policyActions) {
        List<JsonNode> rules = executableActions().stream().map(policyActions::get).filter(rule -> rule != null && rule.isObject()).toList();
        if (rules.size() != VERIFICATION_CONTRACTS.size()) return List.of();
        Set<String> common = hosts(rules.get(0));
        for (JsonNode rule : rules.subList(1, rules.size())) common.retainAll(hosts(rule));
        return common.stream().sorted().toList();
    }

    private static boolean allRulesAllow(List<JsonNode> rules, String host) {
        if (host == null || rules.size() != VERIFICATION_CONTRACTS.size()) return false;
        return rules.stream().allMatch(rule -> hosts(rule).contains(host));
    }

    private static Set<String> hosts(JsonNode rule) {
        Set<String> result = new LinkedHashSet<>();
        for (JsonNode host : rule.path("allowed_hosts")) result.addAll(normalized(List.of(host.asText(""))));
        return result;
    }

    private static Set<String> normalized(List<String> values) {
        Set<String> result = new LinkedHashSet<>();
        for (String value : values) {
            String host = value == null ? "" : value.trim().toLowerCase().replaceAll("\\.$", "");
            if (!host.isEmpty()) result.add(host);
        }
        return result;
    }

    private static boolean isDemoHost(String host) {
        return host != null && (DEMO_HOSTS.contains(host) || host.equals("example.invalid") || host.endsWith(".invalid"));
    }
}
