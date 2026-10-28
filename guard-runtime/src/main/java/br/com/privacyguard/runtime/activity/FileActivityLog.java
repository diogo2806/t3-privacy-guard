package br.com.privacyguard.runtime.activity;

import br.com.privacyguard.runtime.caller.Caller;
import br.com.privacyguard.runtime.caller.GuardFunction;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * JSON lines, one event per call. Each hash covers the previous hash and the event fields, so editing or removing
 * a past line breaks every later hash. On startup the chain is re-verified; a broken chain stops the runtime.
 */
@Component
public class FileActivityLog implements ActivityLog {
    private static final String GENESIS = "0".repeat(64);

    private final Path file;
    private final String tenantId;
    private final ObjectMapper mapper;
    private final Clock clock;
    private final List<ActivityEvent> events = new ArrayList<>();

    public FileActivityLog(
        @Value("${guard-runtime.activity-file:}") String file,
        @Value("${guard-runtime.tenant-id:default}") String tenantId,
        ObjectMapper mapper,
        Clock clock
    ) {
        if (file == null || file.isBlank()) throw new IllegalStateException("guard-runtime.activity-file is required");
        this.file = Path.of(file.trim()).toAbsolutePath().normalize();
        this.tenantId = tenantId == null || tenantId.isBlank() ? "default" : tenantId.trim();
        this.mapper = mapper;
        this.clock = clock;
        load();
    }

    @Override
    public synchronized ActivityEvent append(Caller caller, GuardFunction function, Outcome outcome) {
        long sequence = events.isEmpty() ? 1 : events.get(events.size() - 1).sequence() + 1;
        String previous = events.isEmpty() ? GENESIS : events.get(events.size() - 1).hash();
        List<String> roles = caller.functions().stream().map(GuardFunction::wireName).sorted().toList();
        ActivityEvent unsigned = new ActivityEvent(sequence, "", clock.millis(), "agent", caller.id(), tenantId, CONTRACT_ID,
            function.wireName(), outcome.wireName(), roles);
        ActivityEvent event = withHash(unsigned, chainHash(previous, unsigned));
        try {
            Files.createDirectories(file.getParent());
            Files.write(file, (mapper.writeValueAsString(event) + "\n").getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ex) {
            throw new UncheckedIOException("activity log could not be persisted", ex);
        }
        events.add(event);
        return event;
    }

    @Override
    public synchronized Page read(Long beforeSeq, Long fromMs, Long toMs, int limit) {
        List<ActivityEvent> matching = events.stream()
            .filter(event -> beforeSeq == null || event.sequence() < beforeSeq)
            .filter(event -> fromMs == null || event.timestampMs() >= fromMs)
            .filter(event -> toMs == null || event.timestampMs() <= toMs)
            .sorted(Comparator.comparingLong(ActivityEvent::sequence).reversed())
            .toList();
        List<ActivityEvent> page = matching.stream().limit(limit).toList();
        boolean complete = matching.size() <= limit;
        Long next = complete || page.isEmpty() ? null : page.get(page.size() - 1).sequence();
        return new Page(page, next, complete);
    }

    private void load() {
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (NoSuchFileException ex) {
            return;
        } catch (IOException ex) {
            throw new IllegalStateException("activity log is unreadable", ex);
        }
        String previous = GENESIS;
        for (String line : lines) {
            if (line.isBlank()) continue;
            ActivityEvent event;
            try {
                event = mapper.readValue(line, ActivityEvent.class);
            } catch (IOException ex) {
                throw new IllegalStateException("activity log contains an unreadable entry");
            }
            long expectedSequence = events.size() + 1L;
            if (event.sequence() != expectedSequence || !event.hash().equals(chainHash(previous, event))) {
                throw new IllegalStateException("activity log hash chain is broken at sequence " + expectedSequence);
            }
            events.add(event);
            previous = event.hash();
        }
    }

    private static ActivityEvent withHash(ActivityEvent event, String hash) {
        return new ActivityEvent(event.sequence(), hash, event.timestampMs(), event.callerType(), event.actorDid(), event.onBehalfOfDid(),
            event.contractId(), event.function(), event.outcome(), event.roles());
    }

    static String chainHash(String previous, ActivityEvent event) {
        String material = String.join("\n", previous, Long.toString(event.sequence()), Long.toString(event.timestampMs()), event.callerType(),
            event.actorDid(), event.onBehalfOfDid(), event.contractId(), event.function(), event.outcome(), String.join(",", event.roles()));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }
}
