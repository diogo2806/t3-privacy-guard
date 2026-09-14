package br.com.t3privacyguard.api;

import br.com.t3privacyguard.security.HumanSeparationOfDutiesService;
import br.com.t3privacyguard.security.OperatorLoginAttemptGuard;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextRepository;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class OperatorAuthController {
    private final AuthenticationManager authenticationManager;
    private final OperatorLoginAttemptGuard loginAttemptGuard;
    private final HumanSeparationOfDutiesService separationOfDuties;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();

    public OperatorAuthController(
        AuthenticationManager authenticationManager,
        OperatorLoginAttemptGuard loginAttemptGuard,
        HumanSeparationOfDutiesService separationOfDuties
    ) {
        this.authenticationManager = authenticationManager;
        this.loginAttemptGuard = loginAttemptGuard;
        this.separationOfDuties = separationOfDuties;
    }

    @PostMapping("/login")
    public SessionResponse login(
        @Valid @RequestBody LoginRequest requestBody,
        HttpServletRequest request,
        HttpServletResponse response
    ) {
        loginAttemptGuard.assertAllowed(requestBody.username());

        final Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(requestBody.username(), requestBody.password())
            );
        } catch (AuthenticationException exception) {
            loginAttemptGuard.recordFailure(requestBody.username());
            throw exception;
        }

        loginAttemptGuard.recordSuccess(requestBody.username());
        request.getSession(true);
        request.changeSessionId();

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        return sessionResponse(authentication);
    }

    @GetMapping("/session")
    public SessionResponse session(Authentication authentication) {
        return sessionResponse(authentication);
    }

    @GetMapping("/csrf")
    public CsrfResponse csrf(CsrfToken token) {
        return new CsrfResponse(token.getToken(), token.getHeaderName());
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication
    ) {
        logoutHandler.logout(request, response, authentication);
    }

    private SessionResponse sessionResponse(Authentication authentication) {
        boolean authenticated = authentication != null
            && authentication.isAuthenticated()
            && !"anonymousUser".equals(authentication.getName());
        if (!authenticated) return new SessionResponse(false, null, List.of(), separationOfDuties.enterpriseSodEnabled());
        List<String> authorities = authentication.getAuthorities().stream()
            .map(authority -> authority.getAuthority())
            .filter(authority -> authority.startsWith("ROLE_"))
            .map(authority -> authority.substring("ROLE_".length()))
            .sorted()
            .toList();
        return new SessionResponse(true, authentication.getName(), authorities, separationOfDuties.enterpriseSodEnabled());
    }

    public record LoginRequest(@NotBlank String username, @NotBlank String password) {}
    public record SessionResponse(boolean authenticated, String username, List<String> authorities, boolean enterpriseSeparationOfDuties) {}
    public record CsrfResponse(String token, String headerName) {}
}
