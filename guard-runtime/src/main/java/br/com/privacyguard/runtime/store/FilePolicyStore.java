package br.com.privacyguard.runtime.store;

import br.com.privacyguard.runtime.policy.PolicyDocumentParser;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/** The policy is a file the operator maintains; the runtime only reads it (no versions, no publishing). */
public class FilePolicyStore implements PolicyStore {
    private final Path file;

    public FilePolicyStore(String file) {
        if (file == null || file.isBlank()) throw new IllegalStateException("guard-runtime.policy-file is required");
        this.file = Path.of(file.trim()).toAbsolutePath().normalize();
    }

    @Override
    public Optional<byte[]> current() {
        try (InputStream in = Files.newInputStream(file)) {
            // One byte past the limit is enough for the parser to reject an oversized document as invalid.
            return Optional.of(in.readNBytes(PolicyDocumentParser.MAX_POLICY_BYTES + 1));
        } catch (IOException ex) {
            return Optional.empty();
        }
    }
}
