package br.com.privacyguard.runtime.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.time.Clock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Without a policy directory the policy is the file and cannot be changed through the API. With one, policy is
 * versioned and the file, if present, only seeds new versions.
 */
@Configuration
public class PolicyStoreConfiguration {
    @Bean
    PolicyStore policyStore(
        @Value("${guard-runtime.policy-dir:}") String directory,
        @Value("${guard-runtime.policy-file:}") String file,
        ObjectMapper mapper,
        Clock clock
    ) {
        if (directory == null || directory.isBlank()) return new FilePolicyStore(file);
        Path seed = file == null || file.isBlank() ? null : Path.of(file.trim());
        return new VersionedPolicyStore(Path.of(directory.trim()), seed, mapper, clock);
    }
}
