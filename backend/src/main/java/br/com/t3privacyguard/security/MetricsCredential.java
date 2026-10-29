package br.com.t3privacyguard.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Bearer token for /actuator/prometheus. Without one, metrics are not served. */
@Component
public class MetricsCredential extends StaticTokenCredential {
    public MetricsCredential(@Value("${privacy-guard.metrics.token:}") String token) {
        super(token, "METRICS_TOKEN");
    }
}
