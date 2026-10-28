package br.com.privacyguard.runtime.policy;

import br.com.privacyguard.runtime.contract.ContractText;
import java.util.Collections;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

/** Canonical policy: normalized values, actions and lists in code point order. */
public record PolicyDocument(String version, SortedMap<String, ActionPolicy> actions) {
    public PolicyDocument {
        TreeMap<String, ActionPolicy> sorted = new TreeMap<>(ContractText.CODE_POINT_ORDER);
        sorted.putAll(actions);
        actions = Collections.unmodifiableSortedMap(sorted);
    }

    public record ActionPolicy(
        String purpose,
        List<String> allowedFields,
        List<String> allowedHosts,
        List<String> allowedPrivateRefs,
        boolean requiresHost,
        boolean requiresHumanAuthorization
    ) {
        public ActionPolicy {
            allowedFields = List.copyOf(allowedFields);
            allowedHosts = List.copyOf(allowedHosts);
            allowedPrivateRefs = List.copyOf(allowedPrivateRefs);
        }
    }
}
