package br.com.t3privacyguard.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@Configuration
public class SecurityConfig {
    static final String ANALYST = "ANALYST";
    static final String APPROVER = "APPROVER";
    static final String EXECUTOR = "EXECUTOR";
    static final String AUDITOR = "AUDITOR";

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    UserDetailsService operatorUserDetailsService(
        @Value("${privacy-guard.iam.enterprise-sod-enabled:false}") boolean enterpriseSodEnabled,
        @Value("${privacy-guard.operator.username:}") String operatorUsername,
        @Value("${privacy-guard.operator.password:}") String operatorPassword,
        @Value("${privacy-guard.iam.analyst.username:}") String analystUsername,
        @Value("${privacy-guard.iam.analyst.password:}") String analystPassword,
        @Value("${privacy-guard.iam.approver.username:}") String approverUsername,
        @Value("${privacy-guard.iam.approver.password:}") String approverPassword,
        @Value("${privacy-guard.iam.executor.username:}") String executorUsername,
        @Value("${privacy-guard.iam.executor.password:}") String executorPassword,
        @Value("${privacy-guard.iam.auditor.username:}") String auditorUsername,
        @Value("${privacy-guard.iam.auditor.password:}") String auditorPassword,
        PasswordEncoder passwordEncoder
    ) {
        if (!enterpriseSodEnabled) {
            return new InMemoryUserDetailsManager(buildUser(
                operatorUsername,
                operatorPassword,
                passwordEncoder,
                "OPERATOR_USERNAME",
                "OPERATOR_PASSWORD",
                ANALYST,
                APPROVER,
                EXECUTOR,
                AUDITOR
            ));
        }

        List<UserDetails> users = List.of(
            buildUser(analystUsername, analystPassword, passwordEncoder, "ANALYST_USERNAME", "ANALYST_PASSWORD", ANALYST),
            buildUser(approverUsername, approverPassword, passwordEncoder, "APPROVER_USERNAME", "APPROVER_PASSWORD", APPROVER),
            buildUser(executorUsername, executorPassword, passwordEncoder, "EXECUTOR_USERNAME", "EXECUTOR_PASSWORD", EXECUTOR),
            buildUser(auditorUsername, auditorPassword, passwordEncoder, "AUDITOR_USERNAME", "AUDITOR_PASSWORD", AUDITOR)
        );
        List<String> configuredPrincipals = List.of(
            analystUsername.trim(),
            approverUsername.trim(),
            executorUsername.trim(),
            auditorUsername.trim()
        );
        if (new HashSet<>(configuredPrincipals).size() != configuredPrincipals.size()) {
            throw new IllegalStateException("Enterprise separation of duties requires four distinct human principals");
        }
        return new InMemoryUserDetailsManager(users);
    }

    private static UserDetails buildUser(
        String username,
        String password,
        PasswordEncoder passwordEncoder,
        String usernameProperty,
        String passwordProperty,
        String... roles
    ) {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalStateException(usernameProperty + " and " + passwordProperty + " are required");
        }
        RuntimeSecretPolicy.rejectDocumentationPlaceholder(username, usernameProperty);
        RuntimeSecretPolicy.rejectDocumentationPlaceholder(password, passwordProperty);
        return User.withUsername(username.trim())
            .password(passwordEncoder.encode(password))
            .roles(roles)
            .build();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    @Order(1)
    SecurityFilterChain incidentIntakeSecurityFilterChain(
        HttpSecurity http,
        ObjectMapper objectMapper,
        IncidentIntakeCredentialRegistry intakeCredentials
    ) throws Exception {
        http
            .securityMatcher("/api/integrations/**")
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.POST, "/api/integrations/incidents")
                    .hasAuthority(IncidentIntakeAuthenticationFilter.INTAKE_AUTHORITY)
                .anyRequest().denyAll())
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(new IncidentIntakeAuthenticationFilter(intakeCredentials), UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling(errors -> errors
                .authenticationEntryPoint((request, response, exception) -> writeProblem(
                    objectMapper,
                    response,
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Integration authentication required",
                    "A valid incident intake credential is required."
                ))
                .accessDeniedHandler((request, response, exception) -> writeProblem(
                    objectMapper,
                    response,
                    HttpServletResponse.SC_FORBIDDEN,
                    "Integration action not allowed",
                    "This integration credential is not allowed to perform the requested action."
                )));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain operatorSecurityFilterChain(
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
                .requestMatchers(HttpMethod.POST,
                    "/api/incidents",
                    "/api/agent/analyze",
                    "/api/incidents/*/agent-proposals",
                    "/api/incidents/*/actions",
                    "/api/incidents/*/actions/*/evaluate"
                ).hasRole(ANALYST)
                .requestMatchers(HttpMethod.POST, "/api/incidents/*/actions/*/authorize-remediation").hasRole(APPROVER)
                .requestMatchers(HttpMethod.POST,
                    "/api/incidents/*/actions/*/execute-remediation",
                    "/api/incidents/*/actions/*/verify-remediation"
                ).hasRole(EXECUTOR)
                .anyRequest().hasAnyRole(ANALYST, APPROVER, EXECUTOR, AUDITOR))
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
                    "Your session role is not allowed to perform this action."
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
