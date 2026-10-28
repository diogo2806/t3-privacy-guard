package br.com.privacyguard.runtime.caller;

import java.util.Set;

/** An authenticated workload (proposal agent, protected executor) and the functions it was granted. */
public record Caller(String id, Set<GuardFunction> functions) {
    public Caller {
        functions = Set.copyOf(functions);
    }

    public boolean mayCall(GuardFunction function) {
        return functions.contains(function);
    }

    public boolean isAgent(String agentId) {
        return id.equals(agentId);
    }
}
