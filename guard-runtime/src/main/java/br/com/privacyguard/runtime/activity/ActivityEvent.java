package br.com.privacyguard.runtime.activity;

import java.util.List;

/** Same fields the gateway exposed from the T3N Activity Log, so the backend's audit reconciliation is unchanged. */
public record ActivityEvent(
    long sequence,
    String hash,
    long timestampMs,
    String callerType,
    String actorDid,
    String onBehalfOfDid,
    String contractId,
    String function,
    String outcome,
    List<String> roles
) {
    public ActivityEvent {
        roles = List.copyOf(roles);
    }
}
