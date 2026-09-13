package br.com.t3privacyguard.privacy;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;

class IncidentRetentionPropertiesTest {
    @Test
    void rejectsZeroNegativeAndValuesAboveThirtyDays() {
        try (var factory = Validation.buildDefaultValidatorFactory()) {
            var validator = factory.getValidator();

            IncidentRetentionProperties zero = properties(0);
            IncidentRetentionProperties negative = properties(-1);
            IncidentRetentionProperties tooLong = properties(31);
            IncidentRetentionProperties minimum = properties(1);
            IncidentRetentionProperties maximum = properties(30);

            assertThat(validator.validate(zero)).isNotEmpty();
            assertThat(validator.validate(negative)).isNotEmpty();
            assertThat(validator.validate(tooLong)).isNotEmpty();
            assertThat(validator.validate(minimum)).isEmpty();
            assertThat(validator.validate(maximum)).isEmpty();
        }
    }

    private static IncidentRetentionProperties properties(int days) {
        IncidentRetentionProperties properties = new IncidentRetentionProperties();
        properties.setDays(days);
        return properties;
    }
}
