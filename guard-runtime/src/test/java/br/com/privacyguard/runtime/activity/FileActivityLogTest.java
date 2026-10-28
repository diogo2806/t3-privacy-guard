package br.com.privacyguard.runtime.activity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import br.com.privacyguard.runtime.activity.ActivityLog.Outcome;
import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.GuardFunction;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileActivityLogTest {
    private static final Caller AGENT = new Caller("agent:proposal", Set.of(GuardFunction.EVALUATE_ACTION));
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(1_800_000_000_000L), ZoneOffset.UTC);

    @TempDir
    Path temp;

    private FileActivityLog open(Path file) {
        return new FileActivityLog(file.toString(), "acme", new ObjectMapper(), CLOCK);
    }

    @Test
    void eventsAreChainedPersistedAndPagedNewestFirst() {
        Path file = temp.resolve("activity.jsonl");
        FileActivityLog log = open(file);
        ActivityEvent first = log.append(AGENT, GuardFunction.EVALUATE_ACTION, Outcome.SUCCESS);
        ActivityEvent second = log.append(AGENT, GuardFunction.EXECUTE_REMEDIATION, Outcome.DENIED);
        log.append(AGENT, GuardFunction.EVALUATE_ACTION, Outcome.ERROR);

        assertThat(first.sequence()).isEqualTo(1);
        assertThat(second.hash()).isEqualTo(FileActivityLog.chainHash(first.hash(), second));
        assertThat(second.roles()).containsExactly("evaluate-action");

        FileActivityLog reopened = open(file);
        ActivityLog.Page page = reopened.read(null, null, null, 2);
        assertThat(page.events()).extracting(ActivityEvent::sequence).containsExactly(3L, 2L);
        assertThat(page.complete()).isFalse();
        assertThat(page.nextSequence()).isEqualTo(2L);
        assertThat(reopened.read(page.nextSequence(), null, null, 2).events()).extracting(ActivityEvent::sequence).containsExactly(1L);
        assertThat(reopened.append(AGENT, GuardFunction.EVALUATE_ACTION, Outcome.SUCCESS).sequence()).isEqualTo(4);
    }

    @Test
    void editingAPastEntryStopsTheRuntimeFromStarting() throws Exception {
        Path file = temp.resolve("activity.jsonl");
        FileActivityLog log = open(file);
        log.append(AGENT, GuardFunction.EVALUATE_ACTION, Outcome.DENIED);
        log.append(AGENT, GuardFunction.EVALUATE_ACTION, Outcome.SUCCESS);
        List<String> lines = Files.readAllLines(file);
        Files.write(file, List.of(lines.get(0).replace("\"denied\"", "\"success\""), lines.get(1)));
        assertThatThrownBy(() -> open(file)).isInstanceOf(IllegalStateException.class).hasMessageContaining("hash chain is broken at sequence 1");
    }
}
