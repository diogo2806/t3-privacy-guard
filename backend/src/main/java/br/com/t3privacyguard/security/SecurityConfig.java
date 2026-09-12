package br.com.t3privacyguard.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService operatorUserDetailsService(
        @Value("${privacy-guard.operator.username}") String username,
        @Value("${privacy-guard.operator.password}") String password,
        PasswordEncoder passwordEncoder
    ) {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalStateException("OPERATOR_USERNAME and OPERATOR_PASSWORD are required");
        }
        return new InMemoryUserDetailsManager(
            User.withUsername(username)
                .password(passwordEncoder.encode(password))
                .roles("OPERATOR")
                .build()
        );
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        ObjectMapper objectMapper,
        @Value("${privacy-guard.operator.cookie-secure:false}") boolean cookieSecure
    ) throws Exception {
        CookieCsrfTokenRepository csrfRepository = new CookieCsrfTokenRepository();
        csrfRepository.setCookieName("XSRF-TOKEN");
        csrfRepository.setHeaderName("X-XSRF-TOKEN");
        csrfRepository.setCookiePath("/");
        csrfRepository.setCookieCustomizer(cookie -> cookie
            .httpOnly(true)
            .secure(cookieSecure)
            .sameSite("Strict"));

        http
            .csrf(csrf -> csrf.csrfTokenRepository(csrfRepository))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/auth/login",
                    "/api/auth/session",
                    "/api/auth/csrf",
                    "/actuator/health",
                    "/actuator/health/**"
                ).permitAll()
                .anyRequest().hasRole("OPERATOR"))
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .sessionFixation(fixation -> fixation.migrateSession()))
            .exceptionHandling(errors -> errors
                .authenticationEntryPoint((request, response, exception) -> writeProblem(
                    objectMapper,
                    response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Authentication required",
                    "Your operator session has expired. Sign in again to continue."
                ))
                .accessDeniedHandler((request, response, exception) -> writeProblem(
                    objectMapper,
                    response,
                    HttpServletResponse.SC_FORBIDDEN,
                    "Action not allowed",
                    "Your session is not allowed to perform this action."
                )));

        return http.build();
    }

    private static void writeProblem(
        ObjectMapper objectMapper,
        HttpServletResponse response,
        int status,
        String title,
        String detail
    ) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "about:blank");
        body.put("title", title);
        body.put("status", status);
        body.put("detail", detail);
        objectMapper.writeValue(response.getOutputStream(), body);
    }
}
