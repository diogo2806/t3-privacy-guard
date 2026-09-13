package br.com.t3privacyguard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class PrivacyGuardApplication {
    public static void main(String[] args) {
        SpringApplication.run(PrivacyGuardApplication.class, args);
    }
}
