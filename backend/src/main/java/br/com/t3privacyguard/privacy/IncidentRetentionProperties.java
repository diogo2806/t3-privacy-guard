package br.com.t3privacyguard.privacy;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Component
@ConfigurationProperties(prefix = "privacy-guard.incident-retention")
@Validated
public class IncidentRetentionProperties {
    @Min(1)
    @Max(30)
    private int days = 7;

    public int getDays() {
        return days;
    }

    public void setDays(int days) {
        this.days = days;
    }

    public Duration retention() {
        return Duration.ofDays(days);
    }
}
