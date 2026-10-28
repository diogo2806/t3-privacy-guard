package br.com.privacyguard.runtime.activity;

import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.GuardFunction;
import java.util.List;

/** Replaces the T3N Activity Log: an append-only, hash-chained record of every contract function call. */
public interface ActivityLog {
    String CONTRACT_ID = "guard-runtime";

    ActivityEvent append(Caller caller, GuardFunction function, Outcome outcome);

    /** Newest first, like the T3N log; beforeSeq pages backwards. */
    Page read(Long beforeSeq, Long fromMs, Long toMs, int limit);

    enum Outcome {
        SUCCESS("success"), DENIED("denied"), ERROR("error");

        private final String wireName;

        Outcome(String wireName) {
            this.wireName = wireName;
        }

        public String wireName() {
            return wireName;
        }
    }

    record Page(List<ActivityEvent> events, Long nextSequence, boolean complete) {
        public Page {
            events = List.copyOf(events);
        }
    }
}
